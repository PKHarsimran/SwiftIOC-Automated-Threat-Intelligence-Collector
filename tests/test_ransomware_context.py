from typing import cast

import requests

from swiftioc.ransomware_context import ENDPOINTS, build_context, fetch_context


def payloads():
    return {
        "/victims/recent": [{"victim": "Private Corp", "website": "private.test", "group": "alpha", "country": "US", "activity": "Health", "discovered": "2026-09-22T00:00:00Z"},
                            {"victim": "Other", "website": "other.test", "group": "alpha", "country": "CA", "activity": "Finance", "discovered": "2026-09-22T03:00:00Z"},
                            {"victim": "Missing", "group": "unknown", "country": "N/A", "activity": "Not Found", "discovered": "2026-09-22T04:00:00Z"}],
        "/stats": {"stats": {"victims": 10, "groups": 2, "press": 3, "ignored": "x"}},
        "/listsectors": [{"sector": "Health", "count": 4}],
        "/yara": [{"group": "alpha", "count": 2}],
        "/ransomnotes": [{"group": "alpha", "notes": 3}],
        "/negotiations": [{"group": "alpha", "chats": 1}],
        "/press/recent": [{"title": "Secret", "date": "2026-09-22"}, {"title": "Bad future date", "date": "2027-09-22"}],
    }


def test_context_is_aggregate_only():
    data = build_context(payloads(), "2026-09-22T05:00:00+00:00")
    encoded = str(data)
    assert "Private Corp" not in encoded and "private.test" not in encoded and "Secret" not in encoded
    assert data["activity"]["by_day"] == [{"date": "2026-09-22", "count": 3}]
    assert data["activity"]["groups"] == [{"name": "alpha", "count": 2}]
    assert data["activity"]["sectors"] == [{"name": "Health", "count": 1}, {"name": "Finance", "count": 1}]
    assert data["available"]["yara"] == [{"group": "alpha", "count": 2}]
    assert data["activity"]["press_by_day"] == [{"date": "2026-09-22", "count": 1}]


def test_fetch_uses_seven_bounded_non_redirecting_requests():
    class Response:
        content = b"{}"
        def __init__(self, value): self.value = value
        def raise_for_status(self): return None
        def json(self): return self.value
    class Session:
        def __init__(self): self.calls = []
        def get(self, url, **kwargs):
            assert kwargs["headers"]["X-API-KEY"] == "key"
            assert kwargs["allow_redirects"] is False
            self.calls.append(url)
            endpoint = url.removeprefix("https://api-pro.ransomware.live")
            return Response(payloads()[endpoint])
    session = Session()
    fetch_context("key", cast(requests.Session, session))
    assert len(session.calls) == len(ENDPOINTS) == 7
