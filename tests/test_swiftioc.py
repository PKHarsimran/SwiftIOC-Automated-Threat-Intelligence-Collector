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


def test_extract_indicators_from_text():
    blob = "See https://evil.example.com and 8.8.8.8 plus CVE-2024-0001"
    found = dict((t, v) for t, v in si.extract_indicators_from_text(blob))
    assert "cve" in found
    assert found["cve"] == "CVE-2024-0001"
    types = {t for t, _ in si.extract_indicators_from_text(blob)}
    assert "ipv4" in types


# ------------------------------- STIX -----------------------------------------
def _sample_indicator(**overrides) -> si.Indicator:
    base = dict(
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
    base.update(overrides)
    return si.Indicator(**base)


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
    assert bundle["objects"], "expected at least one indicator object"
    for obj in bundle["objects"]:
        assert obj["id"].startswith("indicator--")
        # Raises ValueError if the suffix is not a valid RFC 4122 UUID.
        uuid.UUID(obj["id"].split("--", 1)[1])
        assert obj["spec_version"] == "2.1"


def test_write_stix_ids_are_deterministic(tmp_path):
    rows = [_sample_indicator()]
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    si.write_stix(a, rows)
    si.write_stix(b, rows)
    id_a = json.loads(a.read_text())["objects"][0]["id"]
    id_b = json.loads(b.read_text())["objects"][0]["id"]
    assert id_a == id_b


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


def test_collect_from_yaml_single_worker_matches(monkeypatch):
    payload = json.dumps({"vulnerabilities": [{"cveID": "CVE-2025-0002", "dateAdded": "2025-01-01"}]})
    monkeypatch.setattr(si, "http_get", lambda *a, **k: payload)
    cfg = {"apis": [{"name": "kev", "parse": "kev", "url": "http://a"}]}
    kwargs = dict(
        window_hours=24 * 3650,
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
    )
    rows_parallel, _, _ = si.collect_from_yaml(cfg, max_workers=4, **kwargs)
    rows_serial, _, _ = si.collect_from_yaml(cfg, max_workers=1, **kwargs)
    assert [r.indicator for r in rows_parallel] == [r.indicator for r in rows_serial]
