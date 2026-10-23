"""Direct tests for swiftioc.http_client.http_get and friends.

Every parser test in test_swiftioc.py monkeypatches si.http_get itself, so
the real implementation (retry/redirect/size-cap/telemetry logic) is never
exercised there. These tests fake requests.Session.get instead, so http_get's
own code actually runs.
"""
from __future__ import annotations

import requests

import swiftioc.http_client as hc


class FakeResponse:
    def __init__(self, status_code=200, headers=None, body=b"", encoding="utf-8",
                 is_redirect=False, is_permanent_redirect=False):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self._body = body
        self.encoding = encoding
        self.is_redirect = is_redirect
        self.is_permanent_redirect = is_permanent_redirect
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} error")

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, timeout=None, stream=None, allow_redirects=None):
        self.calls.append((url, dict(headers or {})))
        return self._responses.pop(0)


def _use_fake_session(monkeypatch, responses):
    fake = FakeSession(responses)
    monkeypatch.setattr(hc, "ensure_session", lambda: fake)
    hc.reset_fetch_metrics()
    return fake


def test_http_get_records_telemetry_before_raising_on_error(monkeypatch):
    _use_fake_session(monkeypatch, [FakeResponse(status_code=500, body=b"boom")])
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected HTTPError"
    except requests.exceptions.HTTPError:
        pass
    metrics = hc.get_fetch_metrics()
    assert metrics["src"]["status"] == 500
    assert metrics["src"]["bytes"] == 4


def test_http_get_returns_body_on_success(monkeypatch):
    _use_fake_session(monkeypatch, [FakeResponse(body=b"hello world")])
    assert hc.http_get("http://feed.example/x", name="src") == "hello world"


def test_authenticated_export_redacts_url_from_logs_and_errors(monkeypatch, caplog):
    secret = "very-private-key"
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{secret}/recent.csv"

    class LeakyResponse(FakeResponse):
        def raise_for_status(self):
            raise requests.exceptions.HTTPError(f"410 Gone for {url}", response=self)

    _use_fake_session(monkeypatch, [LeakyResponse(status_code=410)])
    monkeypatch.setattr(hc, "HTTP_DEBUG", True)
    with caplog.at_level("DEBUG", logger="swiftioc"):
        try:
            hc.http_get(url, name="urlhaus", redact_url=True)
            assert False, "expected failure"
        except requests.exceptions.RequestException as exc:
            assert "HTTP 410" in str(exc)
            assert secret not in str(exc)
    assert secret not in caplog.text


def test_http_get_latency_includes_streamed_body(monkeypatch):
    clock = [10.0]

    class DelayedResponse(FakeResponse):
        def iter_content(self, chunk_size=65536):
            clock[0] += 0.125
            yield from super().iter_content(chunk_size)

    monkeypatch.setattr(hc.time, "perf_counter", lambda: clock[0])
    _use_fake_session(monkeypatch, [DelayedResponse(body=b"body")])
    hc.http_get("http://feed.example/x", name="src")
    assert hc.get_fetch_metrics()["src"]["ms"] == 125


def test_http_get_aggregates_paginated_source_metrics(monkeypatch):
    _use_fake_session(monkeypatch, [FakeResponse(body=b"one"), FakeResponse(body=b"twos")])
    hc.http_get("http://feed.example/one", name="src")
    hc.http_get("http://feed.example/two", name="src")
    assert hc.get_fetch_metrics()["src"] == {"ms": 0, "bytes": 7, "status": 200, "requests": 2}


def test_http_get_allows_parser_specific_headers(monkeypatch):
    fake = _use_fake_session(monkeypatch, [FakeResponse(body=b"ok")])
    hc.http_get("http://feed.example/x", name="src", headers={"apiKey": "test-key"})
    assert fake.calls[0][1]["apiKey"] == "test-key"


def test_http_get_drops_abusech_key_on_cross_origin_redirect(monkeypatch):
    fake = _use_fake_session(monkeypatch, [
        FakeResponse(status_code=302, headers={"Location": "https://93.184.216.34/next"}, is_redirect=True),
        FakeResponse(body=b"ok"),
    ])
    hc.http_get("https://feed.example/x", name="src", headers={"Auth-Key": "private-key"})
    assert fake.calls[0][1]["Auth-Key"] == "private-key"
    assert "Auth-Key" not in fake.calls[1][1]


def test_http_post_json_records_metrics_without_logging_auth_header(monkeypatch, caplog):
    class PostSession:
        def post(self, url, **kwargs):
            assert kwargs["headers"]["Auth-Key"] == "private-key"
            assert kwargs["json"] == {"query": "get_iocs", "days": 2}
            assert kwargs["allow_redirects"] is False
            return FakeResponse(body=b'{"query_status":"ok","data":[]}')

    monkeypatch.setattr(hc, "ensure_session", lambda: PostSession())
    monkeypatch.setattr(hc, "HTTP_DEBUG", True)
    hc.reset_fetch_metrics()
    with caplog.at_level("DEBUG", logger="swiftioc"):
        body = hc.http_post_json("https://threatfox-api.abuse.ch/api/v1/", name="tf",
                                 payload={"query": "get_iocs", "days": 2}, headers={"Auth-Key": "private-key"})
    assert '"query_status":"ok"' in body
    assert hc.get_fetch_metrics()["tf"]["status"] == 200
    assert "private-key" not in caplog.text


def test_http_get_rejects_oversized_content_length(monkeypatch):
    huge = str(hc.MAX_RESPONSE_BYTES + 1)
    _use_fake_session(monkeypatch, [FakeResponse(headers={"Content-Length": huge}, body=b"x")])
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected a size-cap rejection"
    except requests.exceptions.RequestException as e:
        assert "cap" in str(e)


def test_http_get_aborts_streamed_body_over_cap(monkeypatch):
    # No Content-Length header (e.g. chunked/compressed transfer) — the cap
    # must still be enforced while streaming, not just via the header.
    monkeypatch.setattr(hc, "MAX_RESPONSE_BYTES", 10)
    _use_fake_session(monkeypatch, [FakeResponse(body=b"x" * 100)])
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected a size-cap rejection"
    except requests.exceptions.RequestException as e:
        assert "cap" in str(e)


def test_http_get_follows_redirect_to_public_host(monkeypatch):
    fake = _use_fake_session(
        monkeypatch,
        [
            FakeResponse(status_code=302, headers={"Location": "http://93.184.216.34/final"}, is_redirect=True),
            FakeResponse(body=b"final content"),
        ],
    )
    assert hc.http_get("http://feed.example/x", name="src") == "final content"
    assert [url for url, _headers in fake.calls] == ["http://feed.example/x", "http://93.184.216.34/final"]


def test_http_get_blocks_redirect_to_link_local_metadata_ip(monkeypatch):
    _use_fake_session(
        monkeypatch,
        [FakeResponse(status_code=302, headers={"Location": "http://169.254.169.254/latest/meta-data"}, is_redirect=True)],
    )
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected the redirect to be blocked"
    except requests.exceptions.RequestException as e:
        assert "non-public host" in str(e)


def test_http_get_blocks_redirect_to_loopback(monkeypatch):
    _use_fake_session(
        monkeypatch,
        [FakeResponse(status_code=302, headers={"Location": "http://127.0.0.1:8080/admin"}, is_redirect=True)],
    )
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected the redirect to be blocked"
    except requests.exceptions.RequestException as e:
        assert "non-public host" in str(e)


def test_http_get_blocks_redirect_to_non_http_scheme(monkeypatch):
    _use_fake_session(
        monkeypatch,
        [FakeResponse(status_code=302, headers={"Location": "file:///etc/passwd"}, is_redirect=True)],
    )
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected the redirect to be blocked"
    except requests.exceptions.RequestException as e:
        assert "non-http(s) scheme" in str(e)


def test_http_get_caps_redirect_chain_length(monkeypatch):
    responses = [
        FakeResponse(status_code=302, headers={"Location": f"http://93.184.216.34/{i}"}, is_redirect=True)
        for i in range(hc.MAX_REDIRECTS + 2)
    ]
    _use_fake_session(monkeypatch, responses)
    try:
        hc.http_get("http://feed.example/x", name="src")
        assert False, "expected TooManyRedirects"
    except requests.exceptions.TooManyRedirects:
        pass


def test_save_raw_writes_text_file(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "_SAVE_RAW_DIR", tmp_path)
    hc.save_raw("myfeed", "hello", "text")
    assert (tmp_path / "myfeed.txt").read_text(encoding="utf-8") == "hello"


def test_save_raw_writes_binary_file(tmp_path, monkeypatch):
    monkeypatch.setattr(hc, "_SAVE_RAW_DIR", tmp_path)
    hc.save_raw("myfeed", b"\x00\x01binary", "bytes")
    assert (tmp_path / "myfeed.bin").read_bytes() == b"\x00\x01binary"


def test_save_raw_noop_when_dir_unset(monkeypatch):
    monkeypatch.setattr(hc, "_SAVE_RAW_DIR", None)
    hc.save_raw("myfeed", "hello", "text")  # must not raise


def test_load_feedparser_missing_module_raises_systemexit(monkeypatch):
    monkeypatch.setattr(hc, "_FEEDPARSER", None)

    def _raise(name):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(hc, "import_module", _raise)
    try:
        hc.load_feedparser()
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert "feedparser" in str(e)
