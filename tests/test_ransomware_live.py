"""Contract tests for the optional, derived ransomware.live evidence layer."""
import json
import sys
from datetime import datetime, timezone

import requests
import pytest

from swiftioc.ransomware_live import _existing, build_enrichment, fetch_enrichment, main


def test_group_evidence_links_existing_records_without_promoting_candidates(tmp_path):
    feed = tmp_path / "latest.jsonl"
    feed.write_text('{"type":"ipv4","indicator":"1.2.3.4"}\n'
                    '{"type":"cve","indicator":"CVE-2025-1234"}\n', encoding="utf-8")
    data = build_enrichment([
        ("Example", {"ttps": [{"tactic_id": "TA0040", "techniques": [{"technique_id": "T1486"}]}],
                     "vulnerabilities": [{"CVE": "CVE-2025-1234", "CVSS": 9.8}]},
         {"ip": ["1.2.3.4"], "sha256": ["a" * 64], "email": ["bad@example.org"]}),
        ("Other", {"ttps": [], "vulnerabilities": [{"cve": "CVE-2025-1234"}]},
         [{"type": "ip", "ioc": "1.2.3.4"}]),
    ], _existing(feed), "2026-09-21T00:00:00+00:00")
    assert data["groups"][0]["ttps"] == ["T1486"]
    assert data["iocs"] == [
        {"type": "ipv4", "indicator": "1.2.3.4", "groups": ["Example", "Other"], "in_swiftioc": True},
        {"type": "sha256", "indicator": "a" * 64, "groups": ["Example"], "in_swiftioc": False},
    ]
    assert data["cves"] == [{"cve_id": "CVE-2025-1234", "groups": ["Example", "Other"], "in_swiftioc": True}]


def test_api_uses_key_header_and_never_follows_redirect(monkeypatch):
    class Response:
        content = b"{}"
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self.payload

    class Session:
        def __init__(self):
            self.paths = []

        def get(self, url, **kwargs):
            assert kwargs["headers"]["X-API-KEY"] == "secret"
            assert kwargs["allow_redirects"] is False
            self.paths.append(url)
            return Response({"groups": ["A B"]} if url.endswith("/groups") else
                            {"data": {"ttps": ["T1486"], "vulnerabilities": []}} if "/groups/" in url else
                            {"ip": ["1.2.3.4"]})

    monkeypatch.setattr("swiftioc.ransomware_live.time.sleep", lambda _: None)
    session = Session()
    result = fetch_enrichment("secret", set(), session=session)
    assert session.paths[-1].endswith("/iocs/A%20B")
    assert result["iocs"][0]["in_swiftioc"] is False


def test_api_failure_keeps_previous_snapshot_and_does_not_log_key(tmp_path, monkeypatch, capsys):
    feed = tmp_path / "feed.jsonl"
    feed.write_text('{"type":"ipv4","indicator":"1.2.3.4"}\n', encoding="utf-8")
    output = tmp_path / "group_evidence.json"
    output.write_text('{"previous":true}', encoding="utf-8")
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "sensitive-test-key")
    monkeypatch.setattr(sys, "argv", ["ransomware_live", "--feed", str(feed), "--output", str(output)])

    def fail(*_args, **_kwargs):
        raise requests.RequestException("sensitive-test-key")

    monkeypatch.setattr("swiftioc.ransomware_live.fetch_enrichment", fail)
    assert main() == 0
    assert output.read_text(encoding="utf-8") == '{"previous":true}'
    assert "sensitive-test-key" not in capsys.readouterr().out


def test_missing_group_ioc_endpoint_keeps_profile_evidence(monkeypatch):
    class Response:
        content = b"{}"

        def __init__(self, status, payload):
            self.status_code = status
            self.payload = payload

        def json(self):
            return self.payload

    class Session:
        def get(self, url, **_kwargs):
            if url.endswith("/groups"):
                return Response(200, ["A", "B"])
            if url.endswith("/groups/A"):
                return Response(200, {"ttps": ["T1486"], "vulnerabilities": ["CVE-2025-1234"]})
            if url.endswith("/iocs/A"):
                return Response(404, {})
            if url.endswith("/groups/B"):
                return Response(200, {"ttps": [], "vulnerabilities": []})
            return Response(200, {"ip": ["1.2.3.4"]})

    monkeypatch.setattr("swiftioc.ransomware_live.time.sleep", lambda _: None)
    result = fetch_enrichment("key", set(), session=Session())
    assert result["groups_without_ioc_endpoint"] == 1
    assert result["cves"][0]["cve_id"] == "CVE-2025-1234"
    assert result["iocs"][0]["indicator"] == "1.2.3.4"


def test_ioc_group_index_avoids_known_missing_endpoints(monkeypatch):
    class Response:
        content = b"{}"
        status_code = 200

        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    class Session:
        def __init__(self):
            self.paths = []

        def get(self, url, **_kwargs):
            self.paths.append(url)
            if url.endswith("/groups"):
                return Response(["A", "B"])
            if url.endswith("/iocs"):
                return Response({"groups": [{"group": "B"}]})
            if "/groups/" in url:
                return Response({"ttps": [], "vulnerabilities": []})
            return Response({"ip": ["1.2.3.4"]})

    monkeypatch.setattr("swiftioc.ransomware_live.time.sleep", lambda _: None)
    session = Session()
    result = fetch_enrichment("key", set(), session=session)
    assert result["api_calls"] == 5  # Two indexes, two profiles, one IOC.
    assert not any(path.endswith("/iocs/A") for path in session.paths)
    assert result["groups_without_ioc_endpoint"] == 1


def test_fresh_cache_uses_no_api_calls_but_updates_swiftioc_matches(tmp_path, monkeypatch, capsys):
    feed = tmp_path / "feed.jsonl"
    feed.write_text('{"type":"ipv4","indicator":"1.2.3.4"}\n', encoding="utf-8")
    output = tmp_path / "group_evidence.json"
    stamp = datetime.now(timezone.utc).isoformat()
    payload = build_enrichment([("A", {"ttps": [], "vulnerabilities": []}, {"ip": ["1.2.3.4"]})], set(), stamp)
    output.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "secret")
    monkeypatch.setattr(sys, "argv", ["ransomware_live", "--feed", str(feed), "--output", str(output)])
    monkeypatch.setattr("swiftioc.ransomware_live.fetch_enrichment", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("API called")))
    assert main() == 0
    updated = json.loads(output.read_text(encoding="utf-8"))
    assert updated["generated_at"] == stamp
    assert updated["iocs"][0]["in_swiftioc"] is True
    assert "0 API calls" in capsys.readouterr().out


def test_group_limit_stops_before_per_group_requests():
    class Response:
        status_code = 200
        content = b"[]"

        def json(self):
            return [f"group-{index}" for index in range(501)]

    class Session:
        def __init__(self):
            self.calls = 0

        def get(self, _url, **_kwargs):
            self.calls += 1
            return Response()

    session = Session()
    with pytest.raises(ValueError, match="large group listing"):
        fetch_enrichment("key", set(), session=session)
    assert session.calls == 1
