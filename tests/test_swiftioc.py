"""Unit tests for the SwiftIOC collector.

These run fully offline: any parser that would hit the network has its
``http_get`` monkeypatched to return canned payloads, so the suite is safe for
CI and catches feed-format drift without depending on live feeds.
"""
from __future__ import annotations

import csv
import json
import uuid
from datetime import timedelta

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


def test_parse_dt_treats_naive_timestamp_as_utc():
    # abuse.ch-style feeds (URLhaus/MalwareBazaar/Feodo/SSLBL) emit naive
    # "YYYY-MM-DD HH:MM:SS" timestamps with no offset despite "_utc"-suffixed
    # field names. dtparser.parse() on that leaves tzinfo=None, and Python's
    # .astimezone() on a naive datetime silently assumes the HOST machine's
    # local timezone — parse_dt must treat naive input as already UTC.
    dt = si.parse_dt("2024-01-15 10:23:45")
    assert dt is not None
    offset = dt.utcoffset()
    assert offset is not None and offset.total_seconds() == 0
    assert dt.hour == 10 and dt.minute == 23


def test_parse_dt_preserves_explicit_offset():
    dt = si.parse_dt("2024-01-15T10:23:45+05:00")
    assert dt is not None
    offset = dt.utcoffset()
    assert offset is not None and offset.total_seconds() == 0
    assert dt.hour == 5


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


# ------------------------- false-positive filtering ---------------------------
def test_is_false_positive_blocks_ipv4_loopback_url():
    assert si.is_false_positive("url", "http://127.0.0.1:8080/x") is True


def test_is_false_positive_blocks_bracketed_ipv6_loopback_url():
    # Regression: splitting a bracketed IPv6 authority on the first colon
    # yielded "[" instead of the address, so these silently passed as
    # legitimate before is_false_positive was fixed to use _split_authority.
    assert si.is_false_positive("url", "http://[::1]:8080/x") is True


def test_is_false_positive_blocks_bracketed_ipv6_link_local_url_no_port():
    assert si.is_false_positive("url", "http://[fe80::1]/x") is True


def test_is_false_positive_allows_real_url():
    assert si.is_false_positive("url", "http://bad-c2.attacker-controlled.net/x") is False


def test_extract_indicators_from_text():
    blob = "See https://evil.example.com and 8.8.8.8 plus CVE-2024-0001"
    found = dict((t, v) for t, v in si.extract_indicators_from_text(blob))
    assert "cve" in found
    assert found["cve"] == "CVE-2024-0001"
    types = {t for t, _ in si.extract_indicators_from_text(blob)}
    assert "ipv4" in types


def test_extract_indicators_from_text_finds_bare_domains():
    # iocextract has no extract_domains function, so bare-domain mentions
    # (no http(s):// prefix — common phrasing in threat write-ups) must be
    # recovered by our own fallback, not silently dropped.
    blob = "Beware of bare-domain-example-xyz123.tk hosting malware."
    found = dict((t, v) for t, v in si.extract_indicators_from_text(blob))
    assert found.get("domain") == "bare-domain-example-xyz123.tk"


def test_extract_indicators_from_text_ignores_filenames():
    blob = "The dropper saved itself as readme.md and payload.exe on disk."
    values = {v for _, v in si.extract_indicators_from_text(blob)}
    assert "readme.md" not in values
    assert "payload.exe" not in values


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
    # Real URLhaus CSV columns: id,dateadded,url,url_status,last_online,
    # threat,tags,urlhaus_link,reporter. Regression: the parser used to read
    # row[4] (last_online — a timestamp) as the threat, polluting threat/tags
    # with dates. threat is row[5], tags row[6].
    csv_payload = (
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2025-01-01 00:00:00","http://bad.example.com/x","online",'
        '"2025-01-02 03:04:05","malware_download","elf,mips,Mozi","https://urlhaus.abuse.ch/url/1/","rep"\n'
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: csv_payload)
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_urlhaus_csv("http://x", "ref", "urlhaus", ws)
    assert len(out) == 1
    assert out[0].type == "url"
    assert out[0].indicator.startswith("hxxp://")  # defanged
    tags = out[0].tags.split(",")
    assert "malware_download" in tags
    assert "Mozi" in tags  # feed tags carried through
    assert "2025-01-02 03:04:05" not in out[0].tags  # timestamp not leaked
    assert out[0].context == "URLhaus: malware_download"  # threat, not a date
    assert out[0].confidence == "high"


def test_spamhaus_drop_parser(monkeypatch):
    payload = "; comment line\n1.2.3.0/24 ; SBL12345\n# hash comment\nnot-a-cidr\n5.6.7.0/16;SBL999\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_spamhaus_drop("http://x", "ref", "spamhaus_drop", si.now_utc())
    assert len(out) == 2
    assert all(i.type == "ipv4_cidr" for i in out)
    assert {i.indicator for i in out} == {"1.2.3.0/24", "5.6.7.0/16"}


def test_dshield_block_parser(monkeypatch):
    payload = (
        "#\n#   DShield.org Recommended Block List\n#\n"
        "162.217.100.0\t162.217.100.255\t24\t344\tSINGLEHOP-LLC\tUS\tnetops@singlehop.com\n"
        "66.132.172.0\t66.132.172.255\t24\t340\t-\t-\t-\n"
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_dshield_block("http://x", "ref", "dshield_block", si.now_utc())
    assert len(out) == 2
    assert all(i.type == "ipv4_cidr" and i.confidence == "medium" for i in out)
    assert {i.indicator for i in out} == {"162.217.100.0/24", "66.132.172.0/24"}
    with_org = next(i for i in out if i.indicator == "162.217.100.0/24")
    assert "SINGLEHOP-LLC" in with_org.context and "344 targets" in with_org.context
    no_org = next(i for i in out if i.indicator == "66.132.172.0/24")
    assert "(-" not in no_org.context  # placeholder "-" org/country omitted, not leaked into context


def test_dshield_block_parser_skips_malformed_rows(monkeypatch):
    payload = "# header\ntoo\tfew\tcols\n999.999.999.0\t999.999.999.255\t24\t10\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_dshield_block("http://x", "ref", "dshield_block", si.now_utc())
    assert out == []


def test_spamhaus_drop_parser_rejects_out_of_range_octets(monkeypatch):
    # Regression: a digit-only regex admitted 999.999.999.999/24 as a valid
    # CIDR; classify() correctly rejects it via ipaddress.
    payload = "1.2.3.0/24 ; SBL12345\n999.999.999.999/24 ; garbage\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_spamhaus_drop("http://x", "ref", "spamhaus_drop", si.now_utc())
    assert {i.indicator for i in out} == {"1.2.3.0/24"}


def test_openphish_parser(monkeypatch):
    payload = "https://evil.example.com/phish\nnot-a-url\nhttp://also-evil.example.net/x\n\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_openphish("http://x", "ref", "openphish_feed", si.now_utc())
    assert len(out) == 2
    assert all(i.type == "url" for i in out)
    assert all(i.indicator.startswith("hxxp") for i in out)  # defanged


def test_cins_army_parser(monkeypatch):
    payload = "# header\n1.2.3.4\ngarbage-line\n5.6.7.8\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_cins_army("http://x", "ref", "ci_army_list", si.now_utc())
    assert len(out) == 2
    assert all(i.type == "ipv4" and i.confidence == "low" for i in out)


def test_cins_army_parser_rejects_out_of_range_octets(monkeypatch):
    # Regression: a digit-only regex admitted 999.999.999.999 as a valid
    # ipv4 indicator; classify() correctly rejects it via ipaddress.
    payload = "1.2.3.4\n999.999.999.999\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_cins_army("http://x", "ref", "ci_army_list", si.now_utc())
    assert len(out) == 1


def test_tor_exit_parser(monkeypatch):
    payload = "# header\n9.9.9.9\nnot-an-ip\n8.8.8.8\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_tor_exit("http://x", "ref", "tor_exit_nodes", si.now_utc())
    assert len(out) == 2
    assert all("tor" in i.tags for i in out)


def test_tor_exit_parser_rejects_out_of_range_octets(monkeypatch):
    payload = "9.9.9.9\n999.999.999.999\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_tor_exit("http://x", "ref", "tor_exit_nodes", si.now_utc())
    assert len(out) == 1


def test_universal_parser_json(monkeypatch):
    payload = json.dumps(
        [
            {"ip": "1.2.3.4", "first_seen": "2025-01-01T00:00:00Z", "tags": "malware,c2"},
            {"ip": "not-an-indicator"},
        ]
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_universal("http://x", "ref", "universal_feed", ws)
    values = {i.indicator for i in out}
    assert "1[.]2[.]3[.]4" in values or "1.2.3.4" in values


def test_universal_parser_plain_text_fallback(monkeypatch):
    # Not valid JSON, and CSV-sniffing genuinely fails -> the true
    # handle_text() last-resort fallback runs (context == source exactly).
    # Regression: this payload alone doesn't prove the intended branch ran —
    # csv.Sniffer().sniff() succeeds on plain prose surprisingly often
    # (finds a space/comma "delimiter"), so parse_as_csv() silently consumes
    # it first and this test previously passed for the wrong reason.
    import csv

    def raising_sniff(self, sample, delimiters=None):
        raise csv.Error("Could not determine delimiter")

    monkeypatch.setattr(csv.Sniffer, "sniff", raising_sniff)
    payload = "Malicious activity seen from 203.0.113.9 and evil-example.org today."
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_universal("http://x", "ref", "universal_feed", ws)
    types = {i.type for i in out}
    assert "ipv4" in types
    # Proves handle_text(text, context=source, ...) ran, not parse_as_csv().
    assert all(i.context == "universal_feed" for i in out)


def test_universal_parser_csv_with_header(monkeypatch):
    # The legitimate parse_as_csv() success path (a real multi-column feed
    # like a PhishStats-style export) had zero dedicated coverage — every
    # existing "CSV" case was either JSON or, per the regression above,
    # accidentally routed through CSV-sniffing rather than testing it on
    # purpose.
    payload = "ip,first_seen,tags\n1.2.3.4,2025-01-01T00:00:00Z,malware c2\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_universal("http://x", "ref", "universal_feed", ws)
    assert any(i.type == "ipv4" and "1[.]2[.]3[.]4" == i.indicator for i in out)
    assert any(i.context.startswith("universal_feed[1]/") for i in out)


def test_rss_parser_extracts_iocs_from_entries(monkeypatch):
    class FakeEntry:
        title = "New malware campaign"
        summary = "C2 server at 198.51.100.7 delivers payloads via evil-payload.example"
        link = "https://blog.example.com/post"
        published = "2025-06-01T00:00:00Z"
        content = []

    class FakeFeed:
        bozo = 0
        bozo_exception = None
        entries = [FakeEntry()]
        feed = type("F", (), {"updated": None})()

    monkeypatch.setattr(si, "load_feedparser", lambda: type("M", (), {"parse": staticmethod(lambda *a, **k: FakeFeed())}))
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_rss("http://blog.example.com/feed", "ref", "test_blog", ws)
    assert out
    types = {i.type for i in out}
    assert "ipv4" in types
    assert all(i.source == "test_blog" for i in out)


def test_rss_parser_handles_parse_failure(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(si, "load_feedparser", lambda: type("M", (), {"parse": staticmethod(boom)}))
    ws = si.now_utc().replace(year=2000)
    out = si.fetch_rss("http://x", "ref", "test_blog", ws)
    assert out == []


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


# ---------------- high-confidence curated feed ----------------
def test_high_confidence_rows_selection():
    high_score = _sample_indicator(indicator="1.1.1.1", type="ipv4", source="a")
    high_score.score = 90
    corroborated = _sample_indicator(indicator="2.2.2.2", type="ipv4", source="a,b")
    corroborated.score = 55  # below threshold but multi-source
    weak = _sample_indicator(indicator="3.3.3.3", type="ipv4", source="a")
    weak.score = 40  # single source, low score -> excluded

    selected = si.high_confidence_rows([high_score, corroborated, weak], min_score=80)
    values = {r.indicator for r in selected}
    assert values == {"1.1.1.1", "2.2.2.2"}
    assert weak not in selected


def test_high_confidence_rows_respects_threshold():
    ind = _sample_indicator(indicator="4.4.4.4", type="ipv4", source="a")
    ind.score = 70
    assert si.high_confidence_rows([ind], min_score=80) == []
    assert si.high_confidence_rows([ind], min_score=70) == [ind]


def test_apply_retention_age_and_cap():
    now = si.now_utc()

    def ind(name, score, sources, days_old):
        r = _sample_indicator(indicator=name, type="ipv4", source=sources)
        r.score = score
        r.last_seen = si.iso(now - timedelta(days=days_old))
        return r

    rows = [
        ind("1.1.1.1", 90, "a", 1),       # fresh, high
        ind("2.2.2.2", 55, "a,b", 2),      # fresh, corroborated
        ind("3.3.3.3", 80, "a", 40),       # stale -> aged out
        ind("4.4.4.4", 30, "a", 3),        # fresh but weakest
    ]

    # Age filter drops the 40-day-old row.
    kept, aged, pruned = si.apply_retention(rows, max_age_days=30, now=now)
    assert aged == 1 and pruned == 0
    assert "3.3.3.3" not in {r.indicator for r in kept}

    # Cap keeps the top 2 by (score, corroboration, recency): 1.1.1.1 (90) and
    # 2.2.2.2 (55, 2 sources) beat 4.4.4.4 (30).
    kept2, aged2, pruned2 = si.apply_retention(rows, max_age_days=30, max_store=2, now=now)
    assert aged2 == 1 and pruned2 == 1
    assert {r.indicator for r in kept2} == {"1.1.1.1", "2.2.2.2"}
    # Result is ranked strongest-first.
    assert kept2[0].indicator == "1.1.1.1"


def test_apply_retention_tie_break_uses_first_seen_not_last_seen():
    # Regression: last_seen is refreshed to this run's fetch-completion
    # wall-clock time for every re-observed indicator, so it's a fetch-order
    # artifact, not a real recency signal. The tie-break must use first_seen
    # (stable, genuine discovery recency) instead.
    now = si.now_utc()
    older_discovery = _sample_indicator(indicator="1.1.1.1", type="ipv4")
    older_discovery.score = 50
    older_discovery.first_seen = si.iso(now - timedelta(days=10))
    older_discovery.last_seen = si.iso(now)  # refreshed just now by this run

    newer_discovery = _sample_indicator(indicator="2.2.2.2", type="ipv4")
    newer_discovery.score = 50
    newer_discovery.first_seen = si.iso(now - timedelta(hours=1))
    newer_discovery.last_seen = si.iso(now - timedelta(minutes=1))

    kept, _aged, pruned = si.apply_retention([older_discovery, newer_discovery], max_store=1)
    assert pruned == 1
    assert kept[0].indicator == "2.2.2.2"  # genuinely newer discovery wins


def test_apply_retention_noop_by_default():
    rows = [_sample_indicator(indicator=f"{i}.0.0.1", type="ipv4") for i in range(5)]
    kept, aged, pruned = si.apply_retention(rows)
    assert len(kept) == 5 and aged == 0 and pruned == 0


def test_write_dashboard_feed_trims_and_ranks(tmp_path):
    rows = []
    for i, score in enumerate([50, 96, 70]):
        r = _sample_indicator(indicator=f"10.0.0.{i}", type="ipv4")
        r.score = score
        rows.append(r)

    out = tmp_path / "dashboard.jsonl"
    written = si.write_dashboard_feed(out, rows, limit=2)
    assert written == 2
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    # Strongest-first and capped at the limit.
    assert [r["score"] for r in lines] == [96, 70]
    # Trimmed schema: only the fields the dashboard renders.
    assert set(lines[0]) == {
        "indicator", "type", "source", "first_seen", "last_seen",
        "confidence", "score", "sightings", "tags",
    }


def test_write_dashboard_feed_stratifies_by_type(tmp_path):
    # Regression: a pure global top-N-by-score dropped whole categories from
    # the browse preview (e.g. all IPs, which score below the fixed-80
    # CVE/hash band). Every present type must get at least one slot so the
    # flagship table isn't missing a category entirely.
    rows = []
    for i in range(50):  # 50 high-scoring CVEs dominate the global top-N
        r = _sample_indicator(indicator=f"CVE-2025-{1000 + i}", type="cve")
        r.score = 80
        rows.append(r)
    for i in range(50):  # 50 lower-scoring IPs that a global cut would drop
        r = _sample_indicator(indicator=f"10.0.{i}.1", type="ipv4")
        r.score = 30
        rows.append(r)

    out = tmp_path / "dashboard.jsonl"
    written = si.write_dashboard_feed(out, rows, limit=20)
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    types = {r["type"] for r in lines}
    assert written == 20
    assert "ipv4" in types  # would be absent under a pure global top-N
    assert "cve" in types


def test_write_misp_feed_manifest_and_event(tmp_path):
    ind = _sample_indicator(indicator="1.2.3.4", type="ipv4", source="a,b")
    ind.score = 90
    cve = _sample_indicator(indicator="CVE-2025-0001", type="cve")
    cve.score = 80
    ja3 = _sample_indicator(indicator="a" * 32, type="ja3")
    ja3.score = 60
    btc = _sample_indicator(indicator="bc1qtest00000000000000000000000000", type="btc_address")
    btc.score = 50

    out_dir = tmp_path / "misp"
    count = si.write_misp_feed(out_dir, [ind, cve, ja3, btc], run_ts="2025-01-01T00:00:00Z")
    assert count == 4

    manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest) == 1
    event_uuid = next(iter(manifest))
    event = json.loads((out_dir / f"{event_uuid}.json").read_text(encoding="utf-8"))["Event"]
    assert event["uuid"] == event_uuid
    by_value = {a["value"]: a for a in event["Attribute"]}
    assert by_value["1.2.3.4"]["type"] == "ip-dst"
    assert by_value["1.2.3.4"]["category"] == "Network activity"
    assert by_value["1.2.3.4"]["to_ids"] is True
    assert by_value["CVE-2025-0001"]["type"] == "vulnerability"
    assert by_value["CVE-2025-0001"]["category"] == "External analysis"
    assert by_value["CVE-2025-0001"]["to_ids"] is False  # not an observable
    # Regression: TLS fingerprints and BTC addresses previously fell through
    # to the generic "Payload delivery" category, which MISP can reject as
    # an invalid category/type combination on feed import.
    assert by_value["a" * 32]["type"] == "ja3-fingerprint-md5"
    assert by_value["a" * 32]["category"] == "Network activity"
    assert by_value["bc1qtest00000000000000000000000000"]["type"] == "btc"
    assert by_value["bc1qtest00000000000000000000000000"]["category"] == "Financial fraud"


def test_write_misp_feed_event_uuid_stable_across_runs(tmp_path):
    # Regression: a per-run-timestamp UUID would create a brand-new event
    # file every collection and never clean up, growing the repo forever.
    # The event UUID must stay fixed regardless of run_ts so each run
    # overwrites the same event (matching "top IOCs only" retention).
    ind = _sample_indicator(indicator="1.2.3.4", type="ipv4")
    si.write_misp_feed(tmp_path / "a", [ind], run_ts="2025-01-01T00:00:00Z")
    si.write_misp_feed(tmp_path / "b", [ind], run_ts="2026-06-15T12:30:00Z")
    ma = json.loads((tmp_path / "a" / "manifest.json").read_text())
    mb = json.loads((tmp_path / "b" / "manifest.json").read_text())
    assert list(ma.keys()) == list(mb.keys())
    event_files_a = {p.name for p in (tmp_path / "a").glob("*.json") if p.name != "manifest.json"}
    event_files_b = {p.name for p in (tmp_path / "b").glob("*.json") if p.name != "manifest.json"}
    assert event_files_a == event_files_b == {f"{next(iter(ma))}.json"}


def test_write_rss_feed_valid_xml_and_ordering(tmp_path):
    import xml.etree.ElementTree as ET

    old = _sample_indicator(indicator="1.1.1.1", type="ipv4", first_seen="2020-01-01T00:00:00Z", last_seen="2020-01-01T00:00:00Z")
    old.score = 50
    new = _sample_indicator(indicator="2.2.2.2", type="ipv4", first_seen="2025-06-01T00:00:00Z", last_seen="2025-06-01T00:00:00Z")
    new.score = 90

    out = tmp_path / "feed.xml"
    written = si.write_rss_feed(out, [old, new], site_url="https://example.com", limit=10)
    assert written == 2

    root = ET.fromstring(out.read_text(encoding="utf-8"))
    items = root.findall("./channel/item")
    assert len(items) == 2
    # Newest last_seen first.
    title_el = items[0].find("title")
    assert title_el is not None and title_el.text is not None
    assert "2.2.2.2" in title_el.text
    assert "<" not in title_el.text.replace("&lt;", "")  # escaped, not raw


def test_write_rss_feed_strips_illegal_xml_control_chars(tmp_path):
    import xml.etree.ElementTree as ET

    ind = _sample_indicator(indicator="3.3.3.3", type="ipv4")
    ind.context = "malware\x01name"  # raw C0 control char — invalid in XML 1.0
    ind.tags = "c2,\x02bad"

    out = tmp_path / "feed.xml"
    si.write_rss_feed(out, [ind], site_url="https://example.com", limit=10)
    # Must not raise "not well-formed (invalid token)".
    ET.fromstring(out.read_text(encoding="utf-8"))


def test_write_badge_json_shields_schema(tmp_path):
    out = tmp_path / "badge.json"
    si.write_badge_json(out, total=12345, generated="2025-01-01T00:00:00Z")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schemaVersion"] == 1
    assert "12,345" in data["message"]


def test_write_history_appends_and_caps(tmp_path):
    path = tmp_path / "history.json"
    for i in range(5):
        si.write_history(path, {"ts": f"run-{i}", "total": i}, max_entries=3)
    history = json.loads(path.read_text(encoding="utf-8"))
    assert len(history) == 3
    assert [h["total"] for h in history] == [2, 3, 4]  # oldest 2 dropped, order preserved


def test_write_history_tolerates_corrupt_file(tmp_path):
    path = tmp_path / "history.json"
    path.write_text("not json", encoding="utf-8")
    history = si.write_history(path, {"ts": "run-0", "total": 1})
    assert history == [{"ts": "run-0", "total": 1}]


def test_source_count():
    assert si.source_count(_sample_indicator(source="a")) == 1
    assert si.source_count(_sample_indicator(source="a,b,c")) == 3
    assert si.source_count(_sample_indicator(source="")) == 0


# ---------------- summarize_iocs helpers ----------------
def _load_summarizer():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "summarize_iocs.py"
    spec = importlib.util.spec_from_file_location("summarize_iocs", path)
    assert spec is not None and spec.loader is not None
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


def test_merge_with_previous_counts_sightings():
    now_iso = si.iso(si.now_utc())
    # Re-observed indicator with 12 prior sightings -> 13 this run.
    current = [_sample_indicator(indicator="8.8.8.8", first_seen=now_iso, last_seen=now_iso)]
    prev = _sample_indicator(indicator="8.8.8.8", first_seen="2025-01-01T00:00:00Z")
    prev.sightings = 12
    # Brand-new (previous-only) indicator keeps its own count when carried.
    carried_prev = _sample_indicator(indicator="9.9.9.9")
    carried_prev.sightings = 5

    merged, _ = si.merge_with_previous(current, [prev, carried_prev])
    by_key = {m.indicator: m for m in merged}
    assert by_key["8.8.8.8"].sightings == 13
    assert by_key["9.9.9.9"].sightings == 5  # carried untouched
    # A first-ever indicator defaults to 1 sighting.
    fresh, _ = si.merge_with_previous([_sample_indicator(indicator="1.1.1.1")], [])
    assert fresh[0].sightings == 1


def test_sightings_in_csv_and_dashboard_output(tmp_path):
    ind = _sample_indicator(indicator="1.2.3.4", type="ipv4")
    ind.score = 90
    ind.sightings = 42

    csv_out = tmp_path / "latest.csv"
    si.write_csv(csv_out, [ind])
    header = csv_out.read_text(encoding="utf-8").splitlines()[0].split(",")
    row = csv_out.read_text(encoding="utf-8").splitlines()[1].split(",")
    assert "sightings" in header
    assert row[header.index("sightings")] == "42"

    dash_out = tmp_path / "dashboard.jsonl"
    si.write_dashboard_feed(dash_out, [ind])
    rec = json.loads(dash_out.read_text(encoding="utf-8").splitlines()[0])
    assert rec["sightings"] == 42


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


def test_csv_neutralizes_formula_injection(tmp_path):
    # ThreatFox/MalwareBazaar are public-submission feeds; a submitter could
    # set a malware/tag string starting with =/+/-/@ to trigger formula/DDE
    # execution when an analyst opens the exported CSV in Excel (CWE-1236).
    ind = _sample_indicator()
    ind.context = "=cmd|' /C calc'!A0"
    ind.tags = "@SUM(1+1)*cmd"
    out = tmp_path / "latest.csv"
    si.write_csv(out, [ind])
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    header = lines[0].split(",")
    row = next(csv.reader([lines[1]]))
    assert row[header.index("context")].startswith("'=")
    assert row[header.index("tags")].startswith("'@")


def test_csv_leaves_normal_values_untouched(tmp_path):
    ind = _sample_indicator()
    out = tmp_path / "latest.csv"
    si.write_csv(out, [ind])
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert not lines[1].startswith("'")


def test_sslbl_ja3_column_order(monkeypatch):
    # abuse.ch CSV columns are ja3_md5, firstseen, lastseen, listingreason.
    # Regression: the parser previously read ja3/first_seen in swapped columns
    # and returned nothing.
    payload = (
        "################ comment banner ################\n"
        "# ja3_md5,firstseen,lastseen,listingreason\n"
        "b386946a5a44d1ddcc843bc75336dfce,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex\n"
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_sslbl_ja3("http://x", "ref", "sslbl_ja3", si.now_utc().replace(year=2000))
    assert len(out) == 1
    assert out[0].type == "ja3"
    assert out[0].indicator == "b386946a5a44d1ddcc843bc75336dfce"
    assert "Dridex" in out[0].tags
    # SSLBL only lists confirmed-malware C2 fingerprints — high confidence so
    # these scarce IOCs aren't pruned below retention's cut.
    assert out[0].confidence == "high"


def test_malwarebazaar_hash_is_high_confidence(monkeypatch):
    # Parser reads sha256 from row[3] and signature from row[8].
    sha = "a" * 64
    payload = (
        "# comment banner\n"
        '"2025-01-01 00:00:00","md5x","sha1x","' + sha + '","reporter",'
        '"sample.exe","exe","application/x-dosexec","AgentTesla"\n'
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    out = si.fetch_malwarebazaar_csv("http://x", "ref", "mb", si.now_utc().replace(year=2000))
    assert len(out) == 1
    assert out[0].type == "sha256" and out[0].indicator == sha
    # A confirmed malware-sample hash is directly block-ready — high confidence.
    assert out[0].confidence == "high"


def test_nvd_parser_requests_recent_window(monkeypatch):
    # Regression: an unfiltered NVD query returns the oldest CVEs, which the
    # window then drops. The parser must inject lastModStartDate/EndDate.
    captured = {}

    def fake_get(url, *a, **k):
        captured["url"] = url
        return json.dumps({"vulnerabilities": []})

    monkeypatch.setattr(si, "http_get", fake_get)
    si.fetch_nvd_recent(
        "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200",
        "ref", "nvd", si.now_utc(),
    )
    assert "lastModStartDate" in captured["url"]
    assert "lastModEndDate" in captured["url"]


def test_nvd_parser_keeps_old_cve_recently_modified(monkeypatch):
    # Regression: the query is windowed on lastModified (see test above),
    # but the recency gate used to check `published` instead — dropping an
    # old CVE that was merely re-analyzed/re-scored today, which in
    # practice is the majority of what "recently modified" returns. This
    # intermittently zeroed the whole source out in production.
    now = si.now_utc()
    payload = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0567",
                        "published": "2023-03-01T08:15:11.530",
                        "lastModified": si.iso(now),
                        "descriptions": [{"lang": "en", "value": "Old CVE, freshly re-scored"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                    }
                }
            ]
        }
    )
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    ws = now - timedelta(hours=48)
    out = si.fetch_nvd_recent(
        "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200", "ref", "nvd", ws,
    )
    assert len(out) == 1
    assert out[0].indicator == "CVE-2023-0567"
    assert out[0].first_seen.startswith("2023-03-01")  # true original publish date preserved


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


def test_blocklist_txt_plain_ip_feeds(monkeypatch):
    # ET / BinaryDefense / IPsum are plain one-IP-per-line lists with comment
    # headers. Verify they parse, defang, and get source-aware tags so the
    # dashboard tag breakdown is meaningful.
    payload = "# comment header\n100.23.75.120\n1.71.91.53\n\n; another comment\n185.65.202.199\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    ws = si.now_utc().replace(year=2000)

    et = si.fetch_blocklist_txt("http://x", "ref", "et_compromised", ws)
    assert len(et) == 3
    assert all(i.type == "ipv4" for i in et)
    assert si.refang(et[0].indicator) == "100.23.75.120"
    assert "compromised" in et[0].tags

    ipsum = si.fetch_blocklist_txt("http://x", "ref", "ipsum_level5", ws)
    assert "aggregated" in ipsum[0].tags and "ipsum" in ipsum[0].tags

    bd = si.fetch_blocklist_txt("http://x", "ref", "binarydefense_banlist", ws)
    assert "binarydefense" in bd[0].tags


def test_overlapping_ip_feeds_corroborate(monkeypatch):
    # The same IP from three different feeds must dedup to one row whose merged
    # source field drives the corroboration bonus in compute_score.
    ip_payload = "1.2.3.4\n"
    monkeypatch.setattr(si, "http_get", lambda *a, **k: ip_payload)
    cfg = {
        "apis": [
            {"name": "et_compromised", "parse": "blocklist_txt", "url": "http://a"},
            {"name": "binarydefense_banlist", "parse": "blocklist_txt", "url": "http://b"},
            {"name": "ipsum_level5", "parse": "blocklist_txt", "url": "http://c"},
        ]
    }
    rows, counts, _ = si.collect_from_yaml(
        cfg,
        window_hours=24 * 3650,
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
        max_workers=3,
    )
    assert len(rows) == 1
    assert len([s for s in rows[0].source.split(",") if s]) == 3
    # medium base (60) + 2 extra sources * 8 = 76, fresh (no decay).
    assert si.compute_score(rows[0]) == 76
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
