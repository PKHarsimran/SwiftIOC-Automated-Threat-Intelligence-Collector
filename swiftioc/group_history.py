"""Bounded observation history, derived locally without provider requests."""
import json
from datetime import datetime, timedelta, timezone


def update_history(data: dict, previous: dict | None, now: str | None = None) -> None:
    stamp = now or datetime.now(timezone.utc).isoformat()
    old = (previous or {}).get("evidence_history", {})
    observations = dict(old.get("observations", {}))
    current = {}
    for kind, field in (("iocs", "indicator"), ("cves", "cve_id")):
        for record in data.get(kind, []):
            for group in record.get("groups", []):
                item = {"group": group, "kind": kind, "value": record[field],
                        "type": record.get("type", "cve"), "matched": record.get("in_swiftioc", False)}
                current[json.dumps([group, kind, item["type"], item["value"]], ensure_ascii=False)] = item
    for group in data.get("groups", []):
        for technique in group.get("ttps", []):
            item = {"group": group["name"], "kind": "ttps", "type": "technique", "value": technique, "matched": False}
            current[json.dumps([group["name"], "ttps", "technique", technique], ensure_ascii=False)] = item
    events = list(old.get("events", []))
    for key, item in current.items():
        prior = observations.get(key)
        if old and (not prior or not prior.get("present")):
            events.append({**item, "at": stamp, "action": "returned" if prior else "added"})
        if prior and item["matched"] and not prior.get("matched"):
            events.append({**item, "at": stamp, "action": "matched"})
        observations[key] = {**item, "first_observed": prior["first_observed"] if prior else stamp,
                             "last_observed": stamp, "present": True}
    for key, prior in list(observations.items()):
        if key not in current and prior.get("present"):
            events.append({**prior, "at": stamp, "action": "removed"})
            observations[key] = {**prior, "present": False}
    cutoff = (datetime.fromisoformat(stamp) - timedelta(days=90)).isoformat()
    events = [event for event in events if event["at"] >= cutoff]
    observations = {key: item for key, item in observations.items()
                    if item["present"] or item["last_observed"] >= cutoff}
    data["evidence_history"] = {"started_at": old.get("started_at", stamp), "checked_at": stamp,
                                "retention_days": 90, "event_limit": 5000,
                                "truncated": len(events) > 5000 or old.get("truncated", False),
                                "observations": observations, "events": events[-5000:]}
