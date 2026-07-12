"""Unit tests for the SwiftIOC collector.

These run fully offline: any parser that would hit the network has its
``http_get`` monkeypatched to return canned payloads, so the suite is safe for
CI and catches feed-format drift without depending on live feeds.
"""
from __future__ import annotations

import json
import uuid

import pytest

import swiftioc as si


# --------------------------- classification -----------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        ("1.2.3.4", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("10.0.0.0/8", "ipv4_cidr"),
        ("2001:db8::/32", "ipv6_cidr"),
        ("https://example.com/path", "url"),
        ("example.com", "domain"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
        ("CVE-2025-12345", "cve"),
        ("cve-2025-1", None),  # too few digits
        ("user@example.com", "email"),
        ("not an indicator", None),
    ],
)
def test_classify(value, expected):
    assert si.classify(value) == expected


def test_defang_min():
    df = si.defang_min("https://malware.example.com")
    assert df.startswith("hxxps://")
    assert "[.]" in df
    assert "https://" not in df


def test_merge_conf_prefers_higher():
    assert si.merge_conf("low", "high") == "high"
    assert si.merge_conf("high", "medium") == "high"
    assert si.merge_conf("medium", "medium") == "medium"


def test_normalize_value_preserves_url_userinfo_and_port():
    # Only the host must be lowercased; credentials and port are case/value
    # sensitive and must survive untouched (Codex review finding).
    out = si.normalize_value("url", "http://User:Secret@Evil.EXAMPLE:8080/Path?X=1")
    assert out == "http://User:Secret@evil.example:8080/Path?X=1"


def test_normalize_value_preserves_ipv6_literal_authority():
    out = si.normalize_value("url", "http://[2001:DB8::1]:8080/x")
    assert out == "http://[2001:db8::1]:8080/x"


def test_normalize_value_no_userinfo():
    assert si.normalize_value("url", "HTTPS://Evil.COM/Path") == "https://evil.com/Path"


def test_extract_indicators_from_text():
    blob = "See https://evil.example.com and 8.8.8.8 plus CVE-2024-0001"
    found = dict((t, v) for t, v in si.extract_indicators_from_text(blob))
    assert "cve" in found
    assert found["cve"] == "CVE-2024-0001"
    types = {t for t, _ in si.extract_indicators_from_text(blob)}
    assert "ipv4" in types


# ------------------------------- STIX -----------------------------------------
def _sample_indicator(**overrides: str) -> si.Indicator:
    # Construct explicitly and apply overrides via setattr: spreading an
    # untyped dict into the constructor loses per-field types under pyright.
    ind = si.Indicator(
        indicator="8.8.8.8",
        type="ipv4",
        source="test",
        first_seen="2025-01-01T00:00:00Z",
        last_seen="2025-01-01T00:00:00Z",
        confidence="high",
        tlp="CLEAR",
        tags="test",
        reference="https://example.com",
        context="unit test",
    )
    for key, value in overrides.items():
        setattr(ind, key, value)
    return ind


def test_write_stix_uses_valid_uuid_ids(tmp_path):
    rows = [
        _sample_indicator(),
        _sample_indicator(indicator="example.com", type="domain"),
        _sample_indicator(
            indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            type="sha256",
        ),
    ]
    out = tmp_path / "stix2.json"
    si.write_stix(out, rows)
    bundle = json.loads(out.read_text(encoding="utf-8"))

    assert bundle["type"] == "bundle"
    # Bundle id must carry a valid UUID.
    uuid.UUID(bundle["id"].split("--", 1)[1])
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 3
    for obj in indicators:
        assert obj["id"].startswith("indicator--")
        # Raises ValueError if the suffix is not a valid RFC 4122 UUID.
        uuid.UUID(obj["id"].split("--", 1)[1])
        assert obj["spec_version"] == "2.1"
    # Every object id (incl. identity/marking) carries a valid UUID suffix.
    for obj in bundle["objects"]:
        uuid.UUID(obj["id"].split("--", 1)[1])


def test_write_stix_ids_are_deterministic(tmp_path):
    rows = [_sample_indicator()]
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    si.write_stix(a, rows)
    si.write_stix(b, rows)

    def indicator_id(path):
        objs = json.loads(path.read_text())["objects"]
        return next(o["id"] for o in objs if o["type"] == "indicator")

    assert indicator_id(a) == indicator_id(b)


# ----------------------------- changelog --------------------------------------
def test_changelog_is_capped(tmp_path):
    path = tmp_path / "CHANGELOG.md"
    for i in range(60):
        si.write_changelog(path, {"src": i}, total=i, max_entries=50)
    text = path.read_text(encoding="utf-8")
    entries = text.count("\n## ")
    assert entries == 50, f"expected 50 capped entries, found {entries}"
    # Chronological order: newest entry (total 59) must be last.
    assert "Total indicators: **59**" in text
    assert "Total indicators: **9**" not in text  # oldest 10 should be dropped


# ------------------------- parsers (offline) ----------------------------------
def test_urlhaus_parser(monkeypatch):
    csv_payload = (
        "# id,dateadded,url,url_status,threat\n"
        '"1","2025-01-01 00:00:00","http://bad.example.com/x","online","malware_download"\n'
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: csv_payload)
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_urlhaus_csv("http://x", "ref", "urlhaus", ws)
    assert len(out) == 1
    assert out[0].type == "url"
    assert out[0].indicator.startswith("hxxp://")  # defanged


def test_kev_parser(monkeypatch):
    payload = json.dumps(
        {
            "vulnerabilities": [
                {"cveID": "CVE-2025-0001", "dateAdded": "2025-01-01", "shortDescription": "test"},
                {"cveID": None},  # skipped
            ]
        }
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_cisa_kev("http://x", "ref", "cisa_kev", si.now_utc())
    assert len(out) == 1
    assert out[0].indicator == "CVE-2025-0001"
    assert out[0].type == "cve"


# ------------------- orchestration: parallel + dedup --------------------------
def test_collect_from_yaml_dedup_and_counts(monkeypatch):
    kev_payload = json.dumps(
        {"vulnerabilities": [{"cveID": "CVE-2025-0001", "dateAdded": "2025-01-01"}]}
    )

    def fake_get(url, *a, **k):
        return kev_payload

    monkeypatch.setattr(si, "http_get", fake_get)

    cfg = {
        "apis": [
            {"name": "kev_a", "parse": "kev", "url": "http://a"},
            {"name": "kev_b", "parse": "kev", "url": "http://b"},
        ]
    }
    rows, counts, stats = si.collect_from_yaml(
        cfg,
        window_hours=24 * 3650,  # wide window so nothing is filtered out
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
        max_workers=4,
    )
    # Both sources contribute the same CVE -> deduped to a single row whose
    # source field merges both origins.
    assert counts == {"kev_a": 1, "kev_b": 1}
    assert len(rows) == 1
    assert set(rows[0].source.split(",")) == {"kev_a", "kev_b"}
    assert stats["raw_total"] == 2


def test_collect_from_yaml_filters_false_positives(monkeypatch):
    # ThreatFox-style payload mixing a real IP with a bogon/private one.
    payload = json.dumps(
        {
            "data": [
                {"ioc": "8.8.8.8", "ioc_type": "ipv4", "first_seen": "2025-01-01 00:00:00"},
                {"ioc": "10.0.0.5", "ioc_type": "ipv4", "first_seen": "2025-01-01 00:00:00"},
            ]
        }
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    cfg = {"apis": [{"name": "tf", "parse": "threatfox_export_json", "url": "http://a"}]}
    rows, counts, stats = si.collect_from_yaml(
        cfg,
        window_hours=24 * 3650,
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
        max_workers=2,
    )
    values = {si.refang(r.indicator) for r in rows}
    assert "8.8.8.8" in values
    assert "10.0.0.5" not in values  # private/bogon dropped
    assert stats["false_positives_removed"] == 1

    # Disabling the filter keeps everything.
    rows2, _, stats2 = si.collect_from_yaml(
        cfg,
        window_hours=24 * 3650,
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
        max_workers=2,
        fp_filter=False,
    )
    assert stats2["false_positives_removed"] == 0
    assert len(rows2) == 2


def test_domain_case_normalization_dedup(monkeypatch):
    # Two RSS-free API sources emit the same domain in different casing.
    def make_payload(host):
        return json.dumps(
            {"data": [{"ioc": host, "ioc_type": "domain", "first_seen": "2025-01-01 00:00:00"}]}
        )

    payloads = {"http://a": make_payload("Evil.COM"), "http://b": make_payload("evil.com")}
    monkeypatch.setattr(si, "http_get", lambda url, *a, **k: payloads[url])
    cfg = {
        "apis": [
            {"name": "a", "parse": "threatfox_export_json", "url": "http://a"},
            {"name": "b", "parse": "threatfox_export_json", "url": "http://b"},
        ]
    }
    rows, _, _ = si.collect_from_yaml(
        cfg,
        window_hours=24 * 3650,
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
        max_workers=2,
    )
    assert len(rows) == 1  # cased duplicate merged
    assert si.refang(rows[0].indicator) == "evil[.]com".replace("[.]", ".")


def test_stix_covers_all_indicator_types(tmp_path):
    rows = [
        _sample_indicator(indicator="192.0.2.1", type="ipv4"),
        _sample_indicator(indicator="203.0.113.0/24", type="ipv4_cidr"),
        _sample_indicator(indicator="2001:db8::1", type="ipv6"),
        _sample_indicator(indicator="example.org", type="domain"),
        _sample_indicator(indicator="hxxps://bad[.]tld/x", type="url"),
        _sample_indicator(indicator="a" * 128, type="sha512"),
        _sample_indicator(indicator="user@evil.tld", type="email"),
        _sample_indicator(indicator="CVE-2025-9999", type="cve"),
        _sample_indicator(indicator="a" * 32, type="ja3"),
        _sample_indicator(indicator="bc1qtest00000000000000000000000000", type="btc_address"),
    ]
    out = tmp_path / "stix2.json"
    si.write_stix(out, rows)
    bundle = json.loads(out.read_text(encoding="utf-8"))
    by_type = {}
    for obj in bundle["objects"]:
        by_type.setdefault(obj["type"], []).append(obj)

    # Provenance objects present.
    assert len(by_type["identity"]) == 1
    assert len(by_type["marking-definition"]) == 1
    # CVE becomes a vulnerability SDO, not an indicator pattern.
    assert len(by_type["vulnerability"]) == 1
    assert by_type["vulnerability"][0]["name"] == "CVE-2025-9999"
    # Every non-CVE indicator type produced an indicator object (9 of them).
    assert len(by_type["indicator"]) == 9
    for obj in by_type["indicator"]:
        assert obj["created_by_ref"] == si.STIX_IDENTITY_ID
        assert si.STIX_TLP_ID in obj["object_marking_refs"]
        uuid.UUID(obj["id"].split("--", 1)[1])
    # CIDR is emitted and refanged; url pattern is refanged.
    patterns = " ".join(o["pattern"] for o in by_type["indicator"])
    assert "203.0.113.0/24" in patterns
    assert "https://bad.tld/x" in patterns
    assert "SHA-512" in patterns
    # btc_address has no core STIX 2.1 observable; must use a declared custom
    # object rather than the non-existent `cryptocurrency-wallet` type
    # (Codex review finding).
    assert "x-swiftioc-btc-address:value" in patterns
    assert "cryptocurrency-wallet" not in patterns


def test_collect_from_yaml_caps_after_filtering_false_positives(monkeypatch):
    # Regression: --max-per-source must not truncate before FP filtering runs,
    # or early bogon rows can crowd out later legitimate ones (Codex review
    # finding). Three private IPs followed by one public one, capped to 2.
    payload = json.dumps(
        {
            "data": [
                {"ioc": "10.0.0.1", "ioc_type": "ipv4", "first_seen": "2025-01-01 00:00:00"},
                {"ioc": "10.0.0.2", "ioc_type": "ipv4", "first_seen": "2025-01-01 00:00:00"},
                {"ioc": "10.0.0.3", "ioc_type": "ipv4", "first_seen": "2025-01-01 00:00:00"},
                {"ioc": "8.8.8.8", "ioc_type": "ipv4", "first_seen": "2025-01-01 00:00:00"},
            ]
        }
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    cfg = {"apis": [{"name": "tf", "parse": "threatfox_export_json", "url": "http://a"}]}
    rows, counts, _ = si.collect_from_yaml(
        cfg,
        window_hours=24 * 3650,
        skip_rss=True,
        max_per_source=2,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
        max_workers=1,
    )
    values = {si.refang(r.indicator) for r in rows}
    assert "8.8.8.8" in values  # would be truncated away if capped before filtering
    assert counts["tf"] == 1


def test_stix_bundle_validates_against_stix2_library(tmp_path):
    stix2 = pytest.importorskip("stix2")
    rows = [
        _sample_indicator(indicator="192.0.2.1", type="ipv4"),
        _sample_indicator(indicator="203.0.113.0/24", type="ipv4_cidr"),
        _sample_indicator(indicator="example.org", type="domain"),
        _sample_indicator(indicator="hxxps://bad[.]tld/x", type="url"),
        _sample_indicator(indicator="a" * 64, type="sha256"),
        _sample_indicator(indicator="user@evil.tld", type="email"),
        _sample_indicator(indicator="CVE-2025-9999", type="cve"),
        _sample_indicator(indicator="a" * 32, type="ja3"),
    ]
    out = tmp_path / "stix2.json"
    si.write_stix(out, rows)
    # allow_custom=True for the x-swiftioc-ja3 object; raises on any real
    # spec violation (bad ids, marking, pattern syntax, ...).
    bundle = stix2.parse(out.read_text(encoding="utf-8"), allow_custom=True)
    assert len(bundle.objects) == len(rows) + 2  # + identity + marking


# ---------------- summarize_iocs helpers ----------------
def _load_summarizer():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "summarize_iocs.py"
    spec = importlib.util.spec_from_file_location("summarize_iocs", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_summarizer_score_stats_and_top_table():
    mod = _load_summarizer()
    rows = [
        {"indicator": "1.2.3.4", "type": "ipv4", "source": "a,b,c", "score": 96},
        {"indicator": "5.6.7.8", "type": "ipv4", "source": "a", "score": 80},
        {"indicator": "old.example", "type": "domain", "source": "a", "score": 21},
        {"indicator": "unscored.example", "type": "domain", "source": "a"},
    ]
    stats = mod.summarize_scores(rows)
    assert stats["scored"] == 3
    assert stats["corroborated"] == 1
    assert stats["min"] == 21 and stats["max"] == 96
    assert stats["high"] == 2

    top = mod.top_indicators_by_score(rows, limit=2)
    assert len(top) == 2
    assert "1.2.3.4" in top[0][0]  # highest score first
    assert "score 96, 3 sources" == top[0][1]


def test_summarizer_handles_scoreless_feed():
    mod = _load_summarizer()
    rows = [{"indicator": "x.example", "type": "domain", "source": "a"}]
    stats = mod.summarize_scores(rows)
    assert stats == {"scored": 0, "corroborated": 0}
    # render_summary must not crash on legacy score-less data
    summary_md, index_md, step_md = mod.render_summary({}, rows)
    assert "Top indicators by score" in summary_md  # table still renders (score 0)


# ---------------- scoring: corroboration + decay ("living feed") --------------
def _iso_hours_ago(hours: float) -> str:
    from datetime import timedelta

    return si.iso(si.now_utc() - timedelta(hours=hours))


def test_compute_score_fresh_multi_source():
    ind = _sample_indicator(
        confidence="high",
        source="feodo,threatfox,blog",
        last_seen=si.iso(si.now_utc()),
    )
    # base 80 + corroboration capped at +16 = 96, no decay when fresh.
    assert si.compute_score(ind) == 96


def test_compute_score_decays_with_age():
    # ipv4 half-life is 7 days: a high-confidence single-source IP last seen
    # 14 days ago has gone through two half-lives -> 80 * 0.25 = 20.
    ind = _sample_indicator(confidence="high", last_seen=_iso_hours_ago(24 * 14))
    assert si.compute_score(ind) == 20


def test_compute_score_hashes_decay_slowly():
    # sha256 half-life is 180 days; two weeks barely moves it.
    ind = _sample_indicator(
        indicator="a" * 64, type="sha256", confidence="high", last_seen=_iso_hours_ago(24 * 14)
    )
    assert si.compute_score(ind) >= 75


def test_merge_with_previous_carries_and_refreshes():
    now_iso = si.iso(si.now_utc())
    current = [
        _sample_indicator(indicator="8.8.8.8", source="feodo", first_seen=now_iso, last_seen=now_iso),
    ]
    previous = [
        # Re-observed: same key, older first_seen, different source.
        _sample_indicator(
            indicator="8.8.8.8", source="threatfox",
            first_seen="2025-01-01T00:00:00Z", last_seen="2025-06-01T00:00:00Z",
        ),
        # Previous-only: carried forward with its stale last_seen intact.
        _sample_indicator(
            indicator="9.9.9.9", source="cins",
            first_seen="2025-06-01T00:00:00Z", last_seen="2025-06-01T00:00:00Z",
        ),
    ]
    merged, carried = si.merge_with_previous(current, previous)
    assert carried == 1
    by_key = {m.indicator: m for m in merged}
    refreshed = by_key["8.8.8.8"]
    assert refreshed.first_seen == "2025-01-01T00:00:00Z"  # history preserved
    assert refreshed.last_seen == now_iso  # fresh observation wins
    assert set(refreshed.source.split(",")) == {"feodo", "threatfox"}
    assert by_key["9.9.9.9"].last_seen == "2025-06-01T00:00:00Z"  # decays naturally


def test_load_previous_feed_tolerates_garbage_and_filters_fps(tmp_path):
    path = tmp_path / "latest.jsonl"
    good = json.dumps(
        {
            "indicator": "8.8.8.8", "type": "ipv4", "source": "s",
            "first_seen": "2025-01-01T00:00:00Z", "last_seen": "2025-01-01T00:00:00Z",
            "confidence": "high", "tlp": "CLEAR", "tags": "t", "reference": "r",
            "context": "c", "score": 80, "unknown_future_field": "ignored",
        }
    )
    bogon = good.replace("8.8.8.8", "10.0.0.1")
    path.write_text(good + "\n" + bogon + "\nnot json\n" + '{"indicator": "incomplete"}\n', encoding="utf-8")
    loaded = si.load_previous_feed(path)
    assert [i.indicator for i in loaded] == ["8.8.8.8"]
    assert si.load_previous_feed(tmp_path / "missing.jsonl") == []


def test_stix_confidence_uses_computed_score(tmp_path):
    scored = _sample_indicator(indicator="192.0.2.1", type="ipv4")
    scored.score = 96
    unscored = _sample_indicator(indicator="192.0.2.2", type="ipv4", confidence="medium")
    out = tmp_path / "stix.json"
    si.write_stix(out, [scored, unscored])
    bundle = json.loads(out.read_text(encoding="utf-8"))
    confs = {o["name"]: o["confidence"] for o in bundle["objects"] if o["type"] == "indicator"}
    assert confs["ipv4:192.0.2.1"] == 96  # computed score wins
    assert confs["ipv4:192.0.2.2"] == 50  # legacy mapping for unscored rows


def test_csv_includes_score_column(tmp_path):
    ind = _sample_indicator()
    ind.score = 88
    out = tmp_path / "latest.csv"
    si.write_csv(out, [ind])
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert "score" in lines[0].split(",")
    header = lines[0].split(",")
    row = lines[1].split(",")
    assert row[header.index("score")] == "88"


def test_threatfox_export_endpoint_shape(monkeypatch):
    # The real export endpoint returns {"<ioc_id>": [entry, ...]} with
    # ioc_value/first_seen_utc/ip:port/md5_hash spellings and comma-string
    # tags — all of which the parser previously dropped or crashed on.
    payload = json.dumps(
        {
            "1848845": [
                {
                    "ioc_value": "nisosznd.jadoobet.club", "ioc_type": "domain",
                    "threat_type": "payload_delivery", "malware_printable": "ClearFake",
                    "first_seen_utc": "2026-07-12 02:20:08", "confidence_level": 100,
                    "tags": "ClearFake,windows",
                }
            ],
            "1848846": [
                {
                    "ioc_value": "203.0.113.9:4443", "ioc_type": "ip:port",
                    "threat_type": "botnet_cc", "malware_printable": "Emotet",
                    "first_seen_utc": "2026-07-12 01:00:00", "confidence_level": 50,
                }
            ],
            "1848847": [
                {
                    "ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash",
                    "first_seen_utc": "2026-07-12 01:00:00", "confidence_level": 30,
                }
            ],
        }
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_threatfox_export_json("http://x", "ref", "tf", ws)
    by_type = {i.type: i for i in out}
    assert set(by_type) == {"domain", "ipv4", "md5"}
    assert by_type["domain"].confidence == "high"  # confidence_level 100
    assert "clearfake" in by_type["domain"].tags.lower()
    # ip:port strips the port so corroboration can match other IP feeds.
    assert si.refang(by_type["ipv4"].indicator) == "203.0.113.9"
    assert by_type["ipv4"].confidence == "medium"
    assert by_type["md5"].confidence == "low"


def test_threatfox_and_feodo_parsers(monkeypatch):
    tf = json.dumps({"data": [{"ioc": "evil.tld", "ioc_type": "domain", "first_seen": "2025-01-01 00:00:00", "malware": "x"}]})
    monkeypatch.setattr(si, "http_get", lambda *a, **k: tf)
    out = si.fetch_threatfox_export_json("http://x", "ref", "tf", si.now_utc().replace(year=2000))
    assert out and out[0].type == "domain"

    feodo = "first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n2025-01-01,5.5.5.5,443,online,2025-01-02,Emotet\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: feodo)
    out = si.fetch_feodo_ipblocklist("http://x", "ref", "feodo", si.now_utc())
    assert out and out[0].type == "ipv4"
    assert si.refang(out[0].indicator) == "5.5.5.5"


def test_collect_from_yaml_single_worker_matches(monkeypatch):
    payload = json.dumps({"vulnerabilities": [{"cveID": "CVE-2025-0002", "dateAdded": "2025-01-01"}]})
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    cfg = {"apis": [{"name": "kev", "parse": "kev", "url": "http://a"}]}

    def run(max_workers: int) -> list:
        rows, _, _ = si.collect_from_yaml(
            cfg,
            window_hours=24 * 3650,
            skip_rss=True,
            max_per_source=None,
            urlhaus_status="any",
            source_window={},
            grace_on_404=set(),
            ci_safe_rss=False,
            max_workers=max_workers,
        )
        return rows

    rows_parallel = run(4)
    rows_serial = run(1)
    assert [r.indicator for r in rows_parallel] == [r.indicator for r in rows_serial]
