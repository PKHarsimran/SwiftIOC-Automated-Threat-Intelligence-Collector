"""Optional ransomware.live PRO enrichment; raw API responses are never published."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

BASE_URL = "https://api-pro.ransomware.live"
REFRESH_INTERVAL = timedelta(hours=24)
MAX_GROUPS = 500  # Hard cap: at most 1,002 requests in one refresh.
TYPES = {"ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6", "domain": "domain", "url": "url",
         "md5": "md5", "sha1": "sha1", "sha256": "sha256"}
CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.I)
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
HASH_LENGTH = {"md5": 32, "sha1": 40, "sha256": 64}


class APIResponseError(Exception):
    def __init__(self, status: int, endpoint: str):
        self.status = status
        self.endpoint = endpoint
        super().__init__(f"HTTP {status} from {endpoint}")


def _records(value: object, keys: tuple[str, ...] = ()) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in (*keys, "data", "items", "results"):
            if isinstance(value.get(key), list):
                return value[key]
            if isinstance(value.get(key), dict):
                return _records(value[key], keys)
    return []


def _name(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("name", "group", "group_name", "groupname"):
            if isinstance(value.get(key), str):
                return value[key].strip()
    return ""


def _normalise_ioc(kind: str, value: object) -> tuple[str, str] | None:
    kind = TYPES.get(kind.lower().replace("hash_", ""), "")
    if not kind or not isinstance(value, str):
        return None
    value = value.strip().replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
    if not value or len(value) > 2048 or any(ord(char) < 32 for char in value):
        return None
    if kind in ("ipv4", "ipv6"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        kind = f"ipv{address.version}"
        value = address.compressed
    elif kind in HASH_LENGTH:
        if not re.fullmatch(rf"[a-fA-F0-9]{{{HASH_LENGTH[kind]}}}", value):
            return None
        value = value.lower()
    elif kind == "domain":
        value = value.rstrip(".").lower()
        if len(value) > 253 or "." not in value or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
            return None
    elif kind == "url":
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            return None
    return kind, value


def _ioc_pairs(value: object) -> list[tuple[str, str]]:
    """Handle both type-keyed arrays and flat IOC objects without guessing types."""
    result: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key in ("iocs", "indicators", "data"):
            if key in value:
                result.extend(_ioc_pairs(value[key]))
        for key, entries in value.items():
            if key.lower() in TYPES and isinstance(entries, list):
                for item in entries:
                    raw = item if isinstance(item, str) else item.get("ioc", item.get("value", item.get("indicator"))) if isinstance(item, dict) else None
                    pair = _normalise_ioc(key, raw)
                    if pair:
                        result.append(pair)
        kind = value.get("type", value.get("ioc_type"))
        raw = value.get("ioc", value.get("value", value.get("indicator")))
        if isinstance(kind, str):
            pair = _normalise_ioc(kind, raw)
            if pair:
                result.append(pair)
    elif isinstance(value, list):
        for item in value:
            result.extend(_ioc_pairs(item))
    return result


def _ids(value: object, pattern: re.Pattern) -> list[str]:
    found: set[str] = set()
    pending = [value]
    visited = 0
    while pending and visited < 10_000:
        item = pending.pop()
        visited += 1
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and pattern.fullmatch(item.strip()):
            found.add(item.strip().upper())
    return sorted(found)


def _existing(path: Path) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    if not path.exists():
        return found
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            item = json.loads(line)
            kind, value = item.get("type"), item.get("indicator")
            if kind == "cve" and isinstance(value, str) and CVE.fullmatch(value):
                found.add(("cve", value.upper()))
            elif isinstance(kind, str):
                pair = _normalise_ioc(kind, value)
                if pair:
                    found.add(pair)
    return found


def _profile_fields(profile: object) -> str:
    """Schema-only diagnostics; never emit provider values or the API key."""
    if not isinstance(profile, dict):
        return type(profile).__name__
    fields = []
    for key, value in profile.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", key):
            continue
        nested = value[0] if isinstance(value, list) and value else value
        child_keys = ",".join(k for k in nested if isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", k)) if isinstance(nested, dict) else ""
        fields.append(f"{key}({type(value).__name__}{':' + child_keys[:120] if child_keys else ''})")
    return ", ".join(fields[:30])[:900]


def _cached(path: Path) -> dict | None:
    try:
        if not path.is_file() or path.stat().st_size > 5_000_000:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            return None
        if not all(isinstance(data.get(key), list) for key in ("groups", "iocs", "cves")):
            return None
        stamp = datetime.fromisoformat(data["generated_at"])
        if stamp.tzinfo is None or stamp > datetime.now(timezone.utc) + timedelta(minutes=5):
            return None
        return data
    except (OSError, ValueError, TypeError, KeyError):
        return None


def _refresh_membership(data: dict, existing: set[tuple[str, str]]) -> bool:
    changed = False
    for item in data["iocs"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid cached IOC record")
        pair = _normalise_ioc(item.get("type", ""), item.get("indicator")) if isinstance(item.get("type"), str) else None
        current = pair in existing if pair else False
        if item.get("in_swiftioc") is not current:
            item["in_swiftioc"] = current
            changed = True
    for item in data["cves"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid cached CVE record")
        cve = item.get("cve_id")
        current = ("cve", cve.upper()) in existing if isinstance(cve, str) and CVE.fullmatch(cve) else False
        if item.get("in_swiftioc") is not current:
            item["in_swiftioc"] = current
            changed = True
    return changed


def _write_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=".group-evidence-", delete=False) as stream:
        json.dump(data, stream, ensure_ascii=False, separators=(",", ":"))
        temporary = Path(stream.name)
    temporary.replace(path)


def build_enrichment(groups: list[tuple[str, object, object]], existing: set[tuple[str, str]], generated_at: str) -> dict:
    iocs: dict[tuple[str, str], set[str]] = {}
    cves: dict[str, set[str]] = {}
    profiles: list[dict] = []
    for name, profile, indicators in groups:
        if not isinstance(profile, dict):
            raise ValueError(f"Invalid group profile: {name}")
        ttp_ids = _ids(profile.get("ttps", []), TECHNIQUE)
        cve_ids = _ids(profile.get("vulnerabilities", []), CVE)
        profiles.append({"name": name, "ttps": ttp_ids, "cves": cve_ids,
                         "reference": f"https://ransomware.live/group/{quote(name, safe='')}"})
        for cve in cve_ids:
            cves.setdefault(cve, set()).add(name)
        for pair in _ioc_pairs(indicators):
            iocs.setdefault(pair, set()).add(name)
    return {
        "schema_version": 1, "generated_at": generated_at, "source": "Ransomware.live",
        "evidence_label": "Reported group association; not proof of current use or attribution",
        "groups": sorted(profiles, key=lambda item: item["name"].lower()),
        "iocs": [{"type": kind, "indicator": value, "groups": sorted(names), "in_swiftioc": (kind, value) in existing}
                 for (kind, value), names in sorted(iocs.items())],
        "cves": [{"cve_id": cve, "groups": sorted(names), "in_swiftioc": ("cve", cve) in existing}
                 for cve, names in sorted(cves.items())],
    }


def fetch_enrichment(key: str, existing: set[tuple[str, str]], *, session: requests.Session | None = None) -> dict:
    client = session or requests.Session()
    api_calls = 0

    def get(path: str) -> object:
        nonlocal api_calls
        api_calls += 1
        response = client.get(BASE_URL + path, headers={"X-API-KEY": key, "Accept": "application/json"}, timeout=25, allow_redirects=False)
        if not 200 <= response.status_code < 300:
            raise APIResponseError(response.status_code, path.split("/")[1])
        if len(response.content) > 5_000_000:
            raise ValueError("Ransomware.live response exceeds safety limit")
        return response.json()

    listing = get("/groups")
    names = sorted({_name(item) for item in _records(listing, ("groups",)) if _name(item)})
    if not names or len(names) > MAX_GROUPS:
        raise ValueError("Missing or unexpectedly large group listing")
    ioc_listing = get("/iocs")
    listed_ioc_groups = {_name(item).casefold() for item in _records(ioc_listing, ("groups", "iocs")) if _name(item)}
    # If the provider changes the listing shape, use the proven per-group path
    # rather than silently omitting all IOCs.
    known_ioc_groups = listed_ioc_groups if listed_ioc_groups.intersection(name.casefold() for name in names) else None
    groups = []
    ioc_successes = 0
    missing_iocs = 0
    for name in names:
        encoded = quote(name, safe="")
        profile = get(f"/groups/{encoded}")
        if isinstance(profile, dict) and isinstance(profile.get("data"), dict):
            profile = profile["data"]
        if known_ioc_groups is not None and name.casefold() not in known_ioc_groups:
            indicators = {}
            missing_iocs += 1
        else:
            try:
                indicators = get(f"/iocs/{encoded}")
                ioc_successes += 1
            except APIResponseError as error:
                if error.status != 404:
                    raise
                # A stale IOC listing may reference a group with no collection.
                indicators = {}
                missing_iocs += 1
        groups.append((name, profile, indicators))
        time.sleep(0.2)
    if not ioc_successes:
        raise ValueError("No group IOC endpoints were available")
    result = build_enrichment(groups, existing, datetime.now(timezone.utc).isoformat())
    if not result["cves"] and not any(group["ttps"] for group in result["groups"]):
        print(f"::warning::No CVE or ATT&CK IDs parsed from group profiles; first profile fields: {_profile_fields(groups[0][1])}")
    result["groups_without_ioc_endpoint"] = missing_iocs
    result["api_calls"] = api_calls
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a group-evidence sidecar from ransomware.live PRO")
    parser.add_argument("--feed", type=Path, default=Path("public/iocs/latest.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("public/group_evidence.json"))
    parser.add_argument("--force-refresh", action="store_true", help="Explicitly bypass the 24-hour provider cache")
    args = parser.parse_args()
    if not args.feed.exists():
        raise SystemExit("IOC feed is missing; enrichment cannot run")
    existing = _existing(args.feed)
    cached = _cached(args.output)
    if cached:
        try:
            if _refresh_membership(cached, existing):
                _write_atomic(args.output, cached)
        except ValueError:
            cached = None
        else:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(cached["generated_at"])
            if not args.force_refresh and timedelta(0) <= age < REFRESH_INTERVAL:
                print(f"Ransomware.live cache reused ({age.total_seconds() / 3600:.1f}h old); 0 API calls; SwiftIOC matches checked")
                return 0
    key = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")
    if not key:
        print("Ransomware.live enrichment skipped: API key not configured")
        return 0
    try:
        data = fetch_enrichment(key, existing)
        _write_atomic(args.output, data)
        print(f"Ransomware.live enrichment: {len(data['groups'])} groups, {len(data['iocs'])} IOCs, {len(data['cves'])} CVEs; {data['api_calls']} API calls")
    except APIResponseError as error:
        print(f"::warning::Ransomware.live enrichment unavailable (HTTP {error.status} from {error.endpoint}); retaining previous snapshot")
    except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError) as error:
        # Keep the last good sidecar; do not fail the core feed or print request headers.
        print(f"::warning::Ransomware.live enrichment unavailable ({type(error).__name__}); retaining previous snapshot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
