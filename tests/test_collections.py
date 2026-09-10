"""CVE identity and provider evidence must survive collection and persistence."""
import json
from copy import deepcopy
from datetime import timedelta
from typing import Any, Dict

import pytest

import swiftioc as si
from swiftioc.collections import vulnerability_records, write_collections


def indicator(value, kind="cve", **kwargs):
    values: Dict[str, Any] = dict(indicator=value, type=kind, source="nvd", first_seen="2020-01-01T00:00:00Z",
                  last_seen=si.iso(si.now_utc()), confidence="high", tlp="CLEAR", tags="cve,nvd",
                  reference="https://nvd.nist.gov/", context="Description")
    values.update(kwargs)
    return si.Indicator(**values)


def test_collect_keeps_distinct_cves_and_each_providers_evidence(monkeypatch):
    now = si.iso(si.now_utc())
    kev = {"vulnerabilities": [
        {"cveID": "cve-2020-1234", "dateAdded": "2022-02-01", "vendorProject": "Vendor A",
         "product": "Router", "shortDescription": "CISA description", "requiredAction": "Patch",
         "dueDate": "2022-03-01", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "CVE-2020-5678", "dateAdded": "2023-01-01", "product": "Other product"},
        {"cveID": "CVE-2020-1234 trailing text"}, {"cveID": None}, None, 123,
    ]}
    nvd = {"vulnerabilities": [{"cve": {
        "id": cve, "published": "2020-01-01T00:00:00Z", "lastModified": now,
        "descriptions": [{"lang": "en", "value": "NVD description"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
    }} for cve in ["CVE-2020-1234", "CVE-2020-9999", "bad-id"]]}
    monkeypatch.setattr(si, "http_get", lambda url, **kw: json.dumps(kev if kw["name"] == "kev" else nvd))
    rows, counts, _ = si.collect_from_yaml(
        {"apis": [{"name": name, "parse": name, "url": "https://example.invalid"} for name in ["kev", "nvd"]]},
        window_hours=48, skip_rss=True, max_per_source=None, urlhaus_status="any", source_window={},
        grace_on_404=set(), ci_safe_rss=False,
    )
    assert counts == {"kev": 2, "nvd": 2}
    assert len(rows) == 3
    records = {r["cve_id"]: r for r in vulnerability_records(rows)}
    merged = records["CVE-2020-1234"]
    assert merged["sources"] == ["kev", "nvd"]
    assert merged["reports"]["cisa_kev"]["description"] == "CISA description"
    assert merged["reports"]["cisa_kev"]["required_action"] == "Patch"
    assert merged["reports"]["nvd"]["description"] == "NVD description"
    assert merged["reports"]["nvd"]["published_at"] == "2020-01-01T00:00:00Z"
    assert merged["exploitation_status"] == "known_exploited"
    assert records["CVE-2020-5678"]["exploitation_status"] == "known_exploited"
    assert records["CVE-2020-9999"]["exploitation_status"] == "not_established"
    assert next(r for r in rows if r.indicator == "CVE-2020-1234").first_seen == "2020-01-01T00:00:00Z"


def test_provider_evidence_roundtrip_and_missing_source_preservation(tmp_path):
    previous = indicator("CVE-2020-1234", source="kev", vulnerability={"cisa_kev": {
        "required_action": "Old action", "catalog_checked_at": "2026-01-01T00:00:00Z"}})
    path = tmp_path / "latest.jsonl"
    si.write_jsonl(path, [previous])
    baseline = si.load_previous_feed(path)
    before = deepcopy(baseline)
    current = indicator("CVE-2020-1234", vulnerability={"nvd": {"description": "New report"}})
    merged, carried = si.merge_with_previous([current], baseline)
    assert carried == 0
    assert set(merged[0].vulnerability) == {"cisa_kev", "nvd"}
    assert merged[0].vulnerability["cisa_kev"]["catalog_checked_at"] == "2026-01-01T00:00:00Z"
    merged[0].vulnerability["cisa_kev"]["required_action"] = "Mutated"
    assert baseline == before
    carried_rows, carried = si.merge_with_previous([], baseline)
    assert carried == 1
    carried_rows[0].vulnerability["cisa_kev"]["required_action"] = "Also mutated"
    assert baseline == before
    updated, _ = si.merge_with_previous([indicator("CVE-2020-1234", vulnerability={
        "cisa_kev": {"required_action": "Fresh action"}})], baseline)
    assert updated[0].vulnerability["cisa_kev"] == {"required_action": "Fresh action"}


def test_legacy_cve_ids_normalize_and_do_not_claim_structured_kev_evidence(tmp_path):
    path = tmp_path / "latest.jsonl"
    si.write_jsonl(path, [indicator("cve-2020-1234", tags="cve,exploited-in-the-wild")])
    loaded = si.load_previous_feed(path)
    assert loaded[0].indicator == "CVE-2020-1234"
    assert vulnerability_records(loaded)[0]["exploitation_status"] == "reported_exploitation"


def test_typed_exports_partition_and_replace_empty_collection(tmp_path):
    rows = [indicator("CVE-2020-1234", vulnerability={"cisa_kev": {"product": "Router"}}),
            indicator("CVE-2020-2345", tags="cve,exploited-in-the-wild"),
            indicator("CVE-2020-3456"), indicator("8.8.8.8", "ipv4", tags="malware")]
    counts = write_collections(tmp_path, rows, generated_at=si.iso(si.now_utc()))
    assert counts == dict(observables=1, vulnerabilities=3, known_exploited=1,
                          reported_exploitation=1, not_established=1)
    observable = json.loads((tmp_path / "observables.jsonl").read_text())
    assert observable["indicator"] == "8.8.8.8"
    document = json.loads((tmp_path / "vulnerabilities.json").read_text())
    assert document["schema_version"] == 1
    assert [r["cve_id"] for r in document["items"]] == ["CVE-2020-1234", "CVE-2020-2345", "CVE-2020-3456"]
    write_collections(tmp_path, [], generated_at=si.iso(si.now_utc() + timedelta(hours=1)))
    assert json.loads((tmp_path / "vulnerabilities.json").read_text())["items"] == []
    assert (tmp_path / "observables.jsonl").read_text() == ""


@pytest.mark.parametrize("digits", [4, 7, 8, 19])
def test_full_cve_sequence_range_survives_parsers_snapshot_and_collections(digits, monkeypatch, tmp_path):
    cve = "CVE-1900-" + "1" * digits
    now = si.iso(si.now_utc())
    payload = {"vulnerabilities": [{
        "cveID": cve.lower(), "dateAdded": "2026-09-08",
        "cve": {"id": cve.lower(), "lastModified": now},
    }]}
    monkeypatch.setattr(si, "http_get", lambda *args, **kwargs: json.dumps(payload))
    ws = si.now_utc() - timedelta(days=1)
    kev = si.fetch_cisa_kev("https://example.invalid", "ref", "kev", ws)
    nvd = si.fetch_nvd_recent("https://example.invalid", "ref", "nvd", ws)
    assert [r.indicator for r in kev] == [cve]
    assert [r.indicator for r in nvd] == [cve]
    assert si.classify(cve) == "cve"
    assert ("cve", cve) in si.extract_indicators_from_text(f"Advisory ({cve}).")
    path = tmp_path / "latest.jsonl"
    si.write_jsonl(path, kev + nvd)
    loaded = si.load_previous_feed(path)
    assert len(loaded) == 2
    records = vulnerability_records(loaded)
    assert len(records) == 1
    assert records[0]["cve_id"] == cve
    assert set(records[0]["reports"]) == {"cisa_kev", "nvd"}


@pytest.mark.parametrize("cve", ["CVE-1900-123", "CVE-1900-" + "1" * 20, "CVE-1900-１２３４"])
def test_invalid_cve_ids_are_not_accepted_or_truncated(cve, monkeypatch):
    payload = {"vulnerabilities": [{"cveID": cve, "cve": {"id": cve}}]}
    monkeypatch.setattr(si, "http_get", lambda *args, **kwargs: json.dumps(payload))
    ws = si.now_utc() - timedelta(days=1)
    assert si.fetch_cisa_kev("https://example.invalid", "ref", "kev", ws) == []
    assert si.fetch_nvd_recent("https://example.invalid", "ref", "nvd", ws) == []
    assert si.classify(cve) != "cve"
    assert not [r for r in si.extract_indicators_from_text(cve) if r[0] == "cve"]



def test_vulnerability_export_prioritizes_latest_kev_additions_and_publications(tmp_path):
    now = si.parse_dt("2026-09-08T12:00:00Z")
    rows = [
        indicator("CVE-2026-1001", vulnerability={"cisa_kev": {"date_added": "2021-01-01"}}),
        indicator("CVE-1900-1002", vulnerability={"cisa_kev": {"date_added": "2026-09-08"}}),
        indicator("CVE-1900-1003", vulnerability={"nvd": {"published_at": "2026-09-08T10:00:00"}}),
        indicator("CVE-2026-1004", vulnerability={"nvd": {"published_at": "2020-01-01", "modified_at": "2026-09-08T11:30:00Z"}}),
        indicator("CVE-2026-1005", vulnerability={"cisa_kev": {"date_added": "2026-09-08"}, "nvd": {"status": "Rejected"}}),
        indicator("CVE-2026-1006", vulnerability={"nvd": {"published_at": "2030-01-01"}}),
        indicator("CVE-2026-1007", vulnerability={"nvd": {"published_at": "2026-02-30"}}),
    ]
    before = deepcopy(rows)
    expected = ["CVE-1900-1002", "CVE-2026-1001", "CVE-1900-1003", "CVE-2026-1004", "CVE-2026-1006", "CVE-2026-1007", "CVE-2026-1005"]
    assert [r["cve_id"] for r in vulnerability_records(rows, now=now)] == expected
    assert rows == before
    write_collections(tmp_path, rows, generated_at="2026-09-08T12:00:00Z")
    doc = json.loads((tmp_path / "vulnerabilities.json").read_text())
    assert [r["cve_id"] for r in doc["items"]] == expected
    assert doc["counts"]["vulnerabilities"] == 7  # Rejected entries remain auditable.



def test_retention_reserves_space_for_recently_checked_kev_evidence():
    now = si.now_utc()
    high_ioc = indicator("8.8.8.8", "ipv4", score=99)
    old_kev = indicator("CVE-1900-1001", score=95, vulnerability={"cisa_kev": {
        "catalog_checked_at": si.iso(now), "date_added": "2020-01-01"}})
    new_kev = indicator("CVE-1900-1002", score=80, vulnerability={"cisa_kev": {
        "catalog_checked_at": si.iso(now), "date_added": si.iso(now - timedelta(hours=1))}})
    before = deepcopy([high_ioc, old_kev, new_kev])
    kept, aged, pruned = si.apply_retention([high_ioc, old_kev, new_kev], max_store=2, now=now)
    assert [r.indicator for r in kept] == [new_kev.indicator, old_kev.indicator]
    assert aged == 0 and pruned == 1
    one, _, _ = si.apply_retention([old_kev, new_kev], max_store=1, now=now)
    assert one == [new_kev]
    assert [high_ioc, old_kev, new_kev] == before
    cutoff_now = si.parse_dt(si.iso(now))
    assert cutoff_now is not None
    old_kev.vulnerability["cisa_kev"]["catalog_checked_at"] = si.iso(cutoff_now - timedelta(hours=24))
    boundary, _, _ = si.apply_retention([high_ioc, old_kev], max_store=1, now=cutoff_now)
    assert boundary == [old_kev]
    old_kev.vulnerability["cisa_kev"]["catalog_checked_at"] = si.iso(cutoff_now - timedelta(hours=24, seconds=1))
    stale, _, _ = si.apply_retention([high_ioc, old_kev], max_store=1, now=cutoff_now)
    assert stale == [high_ioc]
    new_kev.last_seen = si.iso(now - timedelta(days=40))
    retained, aged, _ = si.apply_retention([high_ioc, new_kev], max_store=1, max_age_days=30, now=now)
    assert retained == [high_ioc] and aged == 1  # Never bypass configured expiry.


@pytest.mark.parametrize(("checked", "status"), [
    (None, "Analyzed"), ("invalid", "Analyzed"),
    ("2020-01-01", "Analyzed"), ("2099-01-01", "Analyzed"),
    ("fresh", "Rejected"),
])
def test_retention_does_not_promote_stale_unknown_future_or_rejected_kev(checked, status):
    now = si.now_utc()
    row = indicator("CVE-1900-1001", score=50, tags="cve,exploited-in-the-wild", vulnerability={
        "cisa_kev": {"catalog_checked_at": si.iso(now) if checked == "fresh" else checked, "date_added": "2020-01-01"},
        "nvd": {"status": status},
    })
    high_ioc = indicator("8.8.8.8", "ipv4", score=99)
    retained, _, _ = si.apply_retention([row, high_ioc], max_store=1, now=now)
    assert retained == [high_ioc]
