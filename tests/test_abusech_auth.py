"""Authenticated abuse.ch feeds must keep working without leaking their key."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

import swiftioc as si


WINDOW = datetime(2026, 10, 21, tzinfo=timezone.utc)


def test_urlhaus_authenticated_export(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "key.with/slash")
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return (
            '# URLhaus export\n'
            '1,2026-10-22 01:00:00,http://evil.example/payload,online,,malware_download,Mirai,https://urlhaus.abuse.ch/url/1/,reporter\n'
        )

    monkeypatch.setattr(si, "http_get", fake_get)
    rows = si.fetch_urlhaus_csv(
        "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv",
        "https://urlhaus.abuse.ch/", "urlhaus_recent_urls", WINDOW,
        auth_key_env="ABUSECH_AUTH_KEY", status_filter="online",
    )
    assert len(rows) == 1
    assert calls[0][0].endswith("/key.with%2Fslash/recent.csv")
    assert calls[0][1]["redact_url"] is True


def test_malwarebazaar_authenticated_export(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "private-key")
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return '2026-10-22 01:00:00,' + 'a' * 64 + ',,,,,,,Mirai\n'

    monkeypatch.setattr(si, "http_get", fake_get)
    rows = si.fetch_malwarebazaar_csv(
        "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv",
        "https://bazaar.abuse.ch/", "malwarebazaar_recent", WINDOW,
        auth_key_env="ABUSECH_AUTH_KEY",
    )
    assert len(rows) == 1
    assert rows[0].indicator == "a" * 64
    assert calls[0][0].endswith("/private-key/recent.csv")
    assert calls[0][1]["redact_url"] is True


def test_threatfox_recent_api_uses_header_and_validates_status(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "private-key")
    monkeypatch.setattr(si.parsers, "now_utc", lambda: datetime(2026, 10, 22, 2, tzinfo=timezone.utc))
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return json.dumps({"query_status": "ok", "data": [{
            "ioc": "evil.example", "ioc_type": "domain", "first_seen": "2026-10-22 01:00:00 UTC",
            "malware_printable": "Mirai", "confidence_level": 90,
        }]})

    monkeypatch.setattr(si, "http_post_json", fake_post)
    rows = si.fetch_threatfox_export_json(
        "https://threatfox-api.abuse.ch/api/v1/", "https://threatfox.abuse.ch/",
        "threatfox_export_json", WINDOW, auth_key_env="ABUSECH_AUTH_KEY",
    )
    assert len(rows) == 1
    assert rows[0].type == "domain"
    assert calls[0][1]["headers"] == {"Auth-Key": "private-key"}
    assert calls[0][1]["payload"] == {"query": "get_iocs", "days": 3}

    monkeypatch.setattr(si, "http_post_json", lambda *args, **kwargs: '{"query_status":"no_api_key"}')
    with pytest.raises(ValueError, match="no_api_key"):
        si.fetch_threatfox_export_json(
            "https://threatfox-api.abuse.ch/api/v1/", "ref", "threatfox_export_json", WINDOW,
            auth_key_env="ABUSECH_AUTH_KEY",
        )


def test_missing_key_fails_before_network(monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.setattr(si, "http_get", lambda *args, **kwargs: pytest.fail("network should not be called"))
    with pytest.raises(ValueError, match="requires the ABUSECH_AUTH_KEY"):
        si.fetch_urlhaus_csv("https://urlhaus-api.abuse.ch/{auth_key}/recent.csv", "ref", "urlhaus", WINDOW,
                              auth_key_env="ABUSECH_AUTH_KEY")
