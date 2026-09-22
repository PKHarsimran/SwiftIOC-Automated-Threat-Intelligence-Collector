"""Build a privacy-minimized ransomware activity summary from PRO endpoints."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from swiftioc.ransomware_live import BASE_URL, _records

REFRESH_INTERVAL = timedelta(hours=24)
ENDPOINTS = ("/victims/recent", "/stats", "/listsectors", "/yara", "/ransomnotes", "/negotiations", "/press/recent")
PLACEHOLDERS = {"", "-", "n/a", "none", "not found", "null", "unknown"}


def _text(item: dict, *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _day(value: str, reference: datetime) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.date() > (reference + timedelta(days=1)).date():
            return ""
        return parsed.date().isoformat()
    except ValueError:
        return ""


def _counts(rows: list[dict], *keys: str, limit: int = 20) -> list[dict]:
    counter = Counter(_text(row, *keys) for row in rows)
    return [{"name": name, "count": count} for name, count in counter.most_common() if name.lower() not in PLACEHOLDERS][:limit]


def _clean_context(data: dict) -> bool:
    changed = False
    for container, keys in ((data.get("activity", {}), ("groups", "countries", "sectors")),
                            (data, ("sector_catalog",))):
        if not isinstance(container, dict):
            continue
        for key in keys:
            rows = container.get(key)
            if not isinstance(rows, list):
                continue
            clean = [row for row in rows if isinstance(row, dict) and isinstance(row.get("name"), str)
                     and row["name"].strip().lower() not in PLACEHOLDERS]
            if clean != rows:
                container[key] = clean
                changed = True
    activity = data.get("activity")
    try:
        reference = datetime.fromisoformat(data["generated_at"])
    except (KeyError, TypeError, ValueError):
        reference = datetime.now(timezone.utc)
    if isinstance(activity, dict):
        for key in ("by_day", "press_by_day"):
            rows = activity.get(key)
            if not isinstance(rows, list):
                continue
            clean = [row for row in rows if isinstance(row, dict) and isinstance(row.get("date"), str)
                     and _day(row["date"], reference)]
            if clean != rows:
                activity[key] = clean
                changed = True
    return changed


def _availability(value: Any, limit: int = 500) -> list[dict]:
    rows = [row for row in _records(value, ("groups", "yara", "ransomnotes", "negotiations")) if isinstance(row, dict)]
    result = []
    for row in rows:
        group = _text(row, "group", "name", "group_name", "groupname")
        if not group:
            continue
        raw_count = next((row.get(key) for key in ("count", "files", "rules", "notes", "chats") if key in row), 1)
        if isinstance(raw_count, (int, float, str)):
            try:
                count = max(0, int(raw_count))
            except ValueError:
                count = 1
        else:
            count = 1
        result.append({"group": group, "count": count})
    return sorted(result, key=lambda item: (-item["count"], item["group"]))[:limit]


def build_context(payloads: dict[str, Any], generated_at: str) -> dict:
    victims = [row for row in _records(payloads.get("/victims/recent"), ("victims",)) if isinstance(row, dict)]
    press = [row for row in _records(payloads.get("/press/recent"), ("press", "cyberattacks")) if isinstance(row, dict)]
    reference = datetime.fromisoformat(generated_at)
    days = Counter(_day(_text(row, "discovered", "attackdate", "published", "date"), reference) for row in victims)
    press_days = Counter(_day(_text(row, "date", "published", "discovered"), reference) for row in press)
    stats_value = payloads.get("/stats", {})
    stats = stats_value.get("stats", stats_value) if isinstance(stats_value, dict) else {}
    public_stats = {}
    for key in ("victims", "groups", "press"):
        value = stats.get(key) if isinstance(stats, dict) else None
        if isinstance(value, (int, float)) and value >= 0:
            public_stats[key] = int(value)
    sectors_raw = [row for row in _records(payloads.get("/listsectors"), ("sectors",)) if isinstance(row, dict)]
    sectors = []
    for row in sectors_raw:
        name = _text(row, "sector", "activity", "name")
        raw_count = row.get("count", row.get("victims", 0))
        if name and name.lower() not in PLACEHOLDERS:
            try:
                sectors.append({"name": name, "count": max(0, int(raw_count))})
            except (TypeError, ValueError):
                continue
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "privacy": "Aggregate counts only; raw victim, domain, note, chat and press records are not published.",
        "sample": {"recent_victims": len(victims), "recent_press": len(press)},
        "stats": public_stats,
        "activity": {
            "by_day": [{"date": day, "count": count} for day, count in sorted(days.items()) if day],
            "press_by_day": [{"date": day, "count": count} for day, count in sorted(press_days.items()) if day],
            "groups": _counts(victims, "group", "group_name"),
            "countries": _counts(victims, "country"),
            "sectors": _counts(victims, "activity", "sector"),
        },
        "sector_catalog": sorted(sectors, key=lambda item: (-item["count"], item["name"]))[:200],
        "available": {
            "yara": _availability(payloads.get("/yara")),
            "ransom_notes": _availability(payloads.get("/ransomnotes")),
            "negotiations": _availability(payloads.get("/negotiations")),
        },
    }


def _cached(path: Path) -> dict | None:
    try:
        if not path.is_file() or path.stat().st_size > 2_000_000:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        stamp = datetime.fromisoformat(data["generated_at"])
        if data.get("schema_version") != 1 or stamp.tzinfo is None or stamp > datetime.now(timezone.utc) + timedelta(minutes=5):
            return None
        return data
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, separators=(",", ":"))
            stream.write("\n")
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def fetch_context(key: str, session: requests.Session | None = None) -> dict:
    client = session or requests.Session()
    payloads = {}
    for endpoint in ENDPOINTS:
        response = client.get(f"{BASE_URL}{endpoint}", headers={"X-API-KEY": key, "Accept": "application/json"},
                              timeout=(5, 30), allow_redirects=False)
        response.raise_for_status()
        if len(response.content) > 10_000_000:
            raise ValueError(f"Oversized response from {endpoint}")
        payloads[endpoint] = response.json()
    return build_context(payloads, datetime.now(timezone.utc).isoformat())


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an aggregate ransomware activity context")
    parser.add_argument("--output", type=Path, default=Path("public/ransomware_context.json"))
    parser.add_argument("--force-refresh", action="store_true")
    args = parser.parse_args()
    cached = _cached(args.output)
    if cached:
        if _clean_context(cached):
            _write(args.output, cached)
        age = datetime.now(timezone.utc) - datetime.fromisoformat(cached["generated_at"])
        if not args.force_refresh and timedelta(0) <= age < REFRESH_INTERVAL:
            print(f"Ransomware context cache reused ({age.total_seconds() / 3600:.1f}h old); 0 API calls")
            return 0
    key = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")
    if not key:
        print("Ransomware context skipped: API key not configured")
        return 0
    try:
        data = fetch_context(key)
        _write(args.output, data)
        print(f"Ransomware context updated; {len(ENDPOINTS)} API calls; aggregate-only output")
    except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"::warning::Ransomware context unavailable ({type(error).__name__}); retaining previous aggregate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
