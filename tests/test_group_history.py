from copy import deepcopy

from swiftioc.group_history import update_history


def snapshot():
    return {"groups": [{"name": "example", "ttps": ["T1486"]}], "cves": [],
            "iocs": [{"type": "ipv4", "indicator": "192.0.2.1", "groups": ["example"], "in_swiftioc": False}]}


def test_baseline_and_cache_are_not_new_activity():
    data = snapshot()
    update_history(data, None, "2026-09-01T00:00:00+00:00")
    assert data["evidence_history"]["events"] == []
    update_history(data, data, "2026-09-02T00:00:00+00:00")
    assert data["evidence_history"]["events"] == []
    assert all(item["first_observed"] == "2026-09-01T00:00:00+00:00" for item in data["evidence_history"]["observations"].values())


def test_add_remove_return_and_feed_match_are_distinct():
    data = snapshot()
    update_history(data, None, "2026-09-01T00:00:00+00:00")
    changed = deepcopy(data)
    changed["iocs"][0]["in_swiftioc"] = True
    changed["groups"][0]["ttps"] = ["T1059"]
    update_history(changed, data, "2026-09-02T00:00:00+00:00")
    assert sorted(event["action"] for event in changed["evidence_history"]["events"]) == ["added", "matched", "removed"]
    returned = snapshot()
    update_history(returned, changed, "2026-09-03T00:00:00+00:00")
    assert any(event["action"] == "returned" and event["value"] == "T1486" for event in returned["evidence_history"]["events"])


def test_history_retention_expires_old_events_and_tombstones():
    data = snapshot()
    update_history(data, None, "2026-01-01T00:00:00+00:00")
    empty: dict = {"groups": [], "iocs": [], "cves": []}
    update_history(empty, data, "2026-01-02T00:00:00+00:00")
    update_history(empty, empty, "2026-09-01T00:00:00+00:00")
    assert empty["evidence_history"]["events"] == []
    assert empty["evidence_history"]["observations"] == {}
