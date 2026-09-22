"""Optional ransomware.live PRO enrichment; raw API responses are never published."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

import requests

BASE_URL = "https://api-pro.ransomware.live"
TYPES = {"ip": "ipv4", "ipv4": "ipv4", "ipv6": "ipv6", "domain": "domain", "url": "url",
         "md5": "md5", "sha1": "sha1", "sha256": "sha256"}
CVE = re.compile(r"^CVE-\d{4}-\d{4,19}$", re.I)
TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
HASH_LENGTH = {"md5": 32, "sha1": 40, "sha256": 64}


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
    for item in _records(value):
        candidates = [item] if isinstance(item, str) else [item.get(key) for key in ("id", "cve", "cve_id", "technique_id", "attack_id") if key in item] if isinstance(item, dict) else []
        for candidate in candidates:
            if isinstance(candidate, str) and pattern.fullmatch(candidate.strip()):
                found.add(candidate.strip().upper())
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

    def get(path: str) -> object:
        response = client.get(BASE_URL + path, headers={"X-API-KEY": key, "Accept": "application/json"}, timeout=25, allow_redirects=False)
        response.raise_for_status()
        if len(response.content) > 5_000_000:
            raise ValueError("Ransomware.live response exceeds safety limit")
        return response.json()

    listing = get("/groups")
    names = sorted({_name(item) for item in _records(listing, ("groups",)) if _name(item)})
    if not names or len(names) > 1000:
        raise ValueError("Missing or unexpectedly large group listing")
    groups = []
    for name in names:
        encoded = quote(name, safe="")
        profile = get(f"/groups/{encoded}")
        if isinstance(profile, dict) and isinstance(profile.get("data"), dict):
            profile = profile["data"]
        indicators = get(f"/iocs/{encoded}")
        groups.append((name, profile, indicators))
        time.sleep(0.2)
    return build_enrichment(groups, existing, datetime.now(timezone.utc).isoformat())


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a group-evidence sidecar from ransomware.live PRO")
    parser.add_argument("--feed", type=Path, default=Path("public/iocs/latest.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("public/group_evidence.json"))
    args = parser.parse_args()
    key = os.environ.get("RANSOMWARE_LIVE_API_KEY", "")
    if not key:
        print("Ransomware.live enrichment skipped: API key not configured")
        return 0
    if not args.feed.exists():
        raise SystemExit("IOC feed is missing; enrichment cannot run")
    try:
        data = fetch_enrichment(key, _existing(args.feed))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=args.output.parent, prefix=".group-evidence-", delete=False) as stream:
            json.dump(data, stream, ensure_ascii=False, separators=(",", ":"))
            temporary = Path(stream.name)
        temporary.replace(args.output)
        print(f"Ransomware.live enrichment: {len(data['groups'])} groups, {len(data['iocs'])} IOCs, {len(data['cves'])} CVEs")
    except (requests.RequestException, ValueError, TypeError, json.JSONDecodeError) as error:
        # Keep the last good sidecar; do not fail the core feed or print request headers.
        print(f"Ransomware.live enrichment unavailable ({type(error).__name__}); retaining previous snapshot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
