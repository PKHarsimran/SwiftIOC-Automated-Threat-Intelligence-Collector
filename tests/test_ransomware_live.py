"""Contract tests for the optional, derived ransomware.live evidence layer."""
import sys

import requests

from swiftioc.ransomware_live import _existing, build_enrichment, fetch_enrichment, main


def test_group_evidence_links_existing_records_without_promoting_candidates(tmp_path):
    feed = tmp_path / "latest.jsonl"
    feed.write_text('{"type":"ipv4","indicator":"1.2.3.4"}\n'
                    '{"type":"cve","indicator":"CVE-2025-1234"}\n', encoding="utf-8")
    data = build_enrichment([
        ("Example", {"ttps": [{"id": "T1486"}], "vulnerabilities": ["CVE-2025-1234"]},
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
