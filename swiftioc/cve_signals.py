"""Small, cached public CVE signal sidecar. Never uses the ransomware.live key."""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from .ransomware_live import _write_atomic

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVE_URL = "https://cveawg.mitre.org/api/cve/"
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,19}\Z")
MAX_GROUP_CVES = 120


def target_ids(feed: Path, group: dict) -> tuple[set[str], list[str]]:
    ids: set[str] = set()
    with feed.open(encoding="utf-8") as stream:
        for line in stream:
            item = json.loads(line)
            value = item.get("indicator")
            if item.get("type") == "cve" and isinstance(value, str) and CVE_ID.fullmatch(value):
                ids.add(value)
    group_ids = sorted({item["cve_id"] for item in group.get("cves", [])
                        if isinstance(item, dict) and isinstance(item.get("cve_id"), str) and CVE_ID.fullmatch(item["cve_id"])})
    if len(group_ids) > MAX_GROUP_CVES:
        raise ValueError("Group CVE count exceeds the bounded enrichment limit")
    return ids | set(group_ids), group_ids


def parse_epss(data: bytes, wanted: set[str]) -> tuple[str | None, dict[str, dict]]:
    if len(data) > 30_000_000:
        raise ValueError("EPSS download exceeds size limit")
    content = gzip.decompress(data).decode("utf-8-sig")
    if len(content) > 50_000_000:
        raise ValueError("EPSS CSV exceeds size limit")
    lines = content.splitlines()
    comment = next((line for line in lines[:4] if line.startswith("#")), "")
    reader = csv.DictReader(line for line in lines if not line.startswith("#"))
    if not {"cve", "epss", "percentile"}.issubset(reader.fieldnames or []):
        raise ValueError("EPSS CSV missing required columns")
    result = {}
    for row in reader:
        cve = row.get("cve", "")
        if cve not in wanted:
            continue
        score, percentile = float(row["epss"]), float(row["percentile"])
        if 0 <= score <= 1 and 0 <= percentile <= 1:
            result[cve] = {"probability": score, "percentile": percentile}
    if not result:
        raise ValueError("EPSS CSV contained no requested CVEs")
    return comment[:200] or None, result


def concise_cve(record: dict, expected: str) -> dict | None:
    meta = record.get("cveMetadata") or {}
    if meta.get("cveId") != expected:
        return None
    status = meta.get("state")
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    description = next((entry.get("value", "") for entry in cna.get("descriptions", [])
                        if isinstance(entry, dict) and entry.get("lang", "").lower().startswith("en")), "")
    affected = []
    for item in cna.get("affected", [])[:15]:
        if not isinstance(item, dict):
            continue
        entry: dict[str, object] = {key: str(item[key])[:160] for key in ("vendor", "product", "packageURL") if isinstance(item.get(key), str)}
        entry["versions"] = [{key: str(version[key])[:100] for key in ("version", "status", "lessThan", "lessThanOrEqual")
                              if isinstance(version.get(key), str)} for version in item.get("versions", [])[:10] if isinstance(version, dict)]
        affected.append(entry)
    ssvc = None
    for adp in containers.get("adp", []):
        if not isinstance(adp, dict) or "CISA" not in str(adp.get("providerMetadata", {}).get("shortName", "")).upper():
            continue
        for metric in adp.get("metrics", []):
            for entry in metric.values() if isinstance(metric, dict) else []:
                content = entry.get("content", entry) if isinstance(entry, dict) and entry.get("type") == "ssvc" else entry
                raw_options = content.get("options") if isinstance(content, dict) else None
                if isinstance(content, dict) and isinstance(raw_options, list):
                    options = {key: value for option in raw_options if isinstance(option, dict)
                               for key, value in option.items() if key in {"Exploitation", "Automatable", "Technical Impact"}}
                    if options:
                        ssvc = {"options": options, "version": content.get("version")}
                        break
    references = [item["url"] for item in cna.get("references", [])[:8]
                  if isinstance(item, dict) and isinstance(item.get("url"), str) and item["url"].startswith("https://")]
    return {"status": status, "updated_at": meta.get("dateUpdated"), "description": description[:1200],
            "affected": affected, "cisa_ssvc": ssvc, "references": references[:5],
            "source_url": f"https://www.cve.org/CVERecord?id={expected}"}


def fresh_cache(path: Path, now: datetime) -> dict | None:
    try:
        if path.stat().st_size > 5_000_000:
            return None
        cached = json.loads(path.read_text(encoding="utf-8"))
        generated = datetime.fromisoformat(cached["generated_at"])
        if cached.get("schema_version") == 1 and isinstance(cached.get("items"), dict) and generated.tzinfo and \
                timedelta(0) <= now - generated < timedelta(hours=24):
            return cached
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return None


def previous_cache(path: Path) -> dict:
    try:
        if path.stat().st_size > 5_000_000:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if value.get("schema_version") == 1 and isinstance(value.get("items"), dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def build(feed: Path, group_file: Path, output: Path, *, session: requests.Session | None = None,
          now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    group = json.loads(group_file.read_text(encoding="utf-8"))
    wanted, group_ids = target_ids(feed, group)
    cached = fresh_cache(output, now)
    # A new CVE during a four-hour collection must not defeat the daily cache.
    # It appears in the next public-signal refresh; the core feed is unaffected.
    if cached:
        return cached
    previous = previous_cache(output)
    client = session or requests.Session()
    items = {cve: {} for cve in sorted(wanted)}
    epss_date = None
    try:
        response = client.get(EPSS_URL, timeout=30)
        response.raise_for_status()
        epss_date, scores = parse_epss(response.content, wanted)
        for cve, score in scores.items():
            items[cve]["epss"] = score
    except (requests.RequestException, OSError, ValueError, EOFError):
        if previous:
            return previous
        raise
    for cve in group_ids:
        try:
            response = client.get(CVE_URL + cve, timeout=15, headers={"Accept": "application/json"})
            response.raise_for_status()
            if len(response.content) > 500_000:
                raise ValueError("CVE record exceeds size limit")
            detail = concise_cve(response.json(), cve)
            if detail:
                detail["checked_at"] = now.isoformat()
                items[cve]["official_cve"] = detail
        except (requests.RequestException, ValueError, TypeError):
            old = previous.get("items", {}).get(cve, {})
            if isinstance(old, dict) and "official_cve" in old:
                items[cve]["official_cve"] = old["official_cve"]
    data = {"schema_version": 1, "generated_at": now.isoformat(), "group_snapshot_at": group.get("generated_at"),
            "epss_header": epss_date, "scope": "EPSS is a forecast, not exploitation evidence. CVE/SSVC claims remain source-specific.",
            "sources": {"epss": "https://www.first.org/epss/data", "cve": "https://www.cve.org/"}, "items": items}
    _write_atomic(output, data)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh public EPSS and official CVE signal sidecar")
    parser.add_argument("--feed", type=Path, default=Path("public/iocs/latest.jsonl"))
    parser.add_argument("--groups", type=Path, default=Path("public/group_evidence.json"))
    parser.add_argument("--output", type=Path, default=Path("public/cve_signals.json"))
    args = parser.parse_args()
    try:
        data = build(args.feed, args.groups, args.output)
        print(f"Public CVE signals: {len(data['items'])} identities; no ransomware.live calls")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"::warning::Public CVE signals unavailable: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
