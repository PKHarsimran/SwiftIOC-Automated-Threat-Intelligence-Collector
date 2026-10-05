"""Bounded ATT&CK detection guidance for reported group techniques."""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

from .ransomware_live import _write_atomic

SOURCE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?\Z")


def _external(obj: dict, prefix: str) -> tuple[str | None, str | None]:
    for entry in obj.get("external_references", []):
        if isinstance(entry, dict) and str(entry.get("external_id", "")).startswith(prefix):
            return entry["external_id"], entry.get("url")
    return None, None


def compact(bundle: dict, wanted: set[str], generated_at: str) -> dict:
    objects = bundle.get("objects")
    if not isinstance(objects, list) or len(objects) < 1000:
        raise ValueError("ATT&CK STIX bundle is incomplete")
    by_stix = {obj.get("id"): obj for obj in objects if isinstance(obj, dict) and isinstance(obj.get("id"), str)
               and obj.get("revoked") is not True and obj.get("x_mitre_deprecated") is not True}
    techniques = {obj["id"]: external for obj in by_stix.values() if obj.get("type") == "attack-pattern"
                  if (external := _external(obj, "T"))[0] in wanted}
    result = {value[0]: {"technique_url": value[1], "strategies": []} for value in techniques.values()}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship" or obj.get("relationship_type") != "detects":
            continue
        target = techniques.get(obj.get("target_ref"))
        strategy = by_stix.get(obj.get("source_ref"))
        if not target or not strategy or strategy.get("type") != "x-mitre-detection-strategy":
            continue
        strategy_id, url = _external(strategy, "DET")
        if not strategy_id or not url:
            continue
        analytics = []
        for ref in strategy.get("x_mitre_analytic_refs", [])[:8]:
            analytic = by_stix.get(ref)
            if not analytic or analytic.get("type") != "x-mitre-analytic":
                continue
            analytic_id, analytic_url = _external(analytic, "AN")
            if not analytic_id:
                continue
            sources = [row.get("name", "")[:100] for row in analytic.get("x_mitre_log_source_references", [])[:5]
                       if isinstance(row, dict) and isinstance(row.get("name"), str)]
            analytics.append({"id": analytic_id, "url": analytic_url or url, "platforms": analytic.get("x_mitre_platforms", [])[:8],
                              "log_sources": sources})
        result[target[0]]["strategies"].append({"id": strategy_id, "name": str(strategy.get("name", ""))[:180],
                                                  "url": url, "analytics": analytics[:5]})
    for item in result.values():
        item["strategies"] = sorted(item["strategies"], key=lambda row: row["id"])[:6]
    return {"schema_version": 1, "generated_at": generated_at, "source": "MITRE ATT&CK Enterprise STIX 2.1",
            "source_url": "https://github.com/mitre-attack/attack-stix-data", "scope": "Technique-level guidance; not proof of a deployed or effective detection.",
            "requested_techniques": sorted(wanted), "techniques": result}


def build(group_file: Path, output: Path, *, session: requests.Session | None = None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    group = json.loads(group_file.read_text(encoding="utf-8"))
    wanted = {value for item in group.get("groups", []) if isinstance(item, dict) for value in item.get("ttps", [])
              if isinstance(value, str) and TECHNIQUE.fullmatch(value)}
    if len(wanted) > 1000:
        raise ValueError("Too many reported techniques")
    try:
        previous = json.loads(output.read_text(encoding="utf-8"))
        age = now - datetime.fromisoformat(previous["generated_at"])
        # Newly reported techniques wait for the next weekly refresh rather
        # than forcing a full upstream bundle download every collection run.
        if previous.get("schema_version") == 1 and previous.get("techniques") and 0 <= age.total_seconds() < 7 * 86400:
            return previous
    except (OSError, ValueError, TypeError, KeyError):
        pass
    client = session or requests.Session()
    response = client.get(SOURCE, timeout=40)
    response.raise_for_status()
    if len(response.content) > 70_000_000:
        raise ValueError("ATT&CK bundle exceeds size limit")
    data = compact(response.json(), wanted, now.isoformat())
    _write_atomic(output, data)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh ATT&CK detection guidance sidecar")
    parser.add_argument("--groups", type=Path, default=Path("public/group_evidence.json"))
    parser.add_argument("--output", type=Path, default=Path("public/attack_guidance.json"))
    args = parser.parse_args()
    try:
        data = build(args.groups, args.output)
        print(f"ATT&CK guidance: {len(data['techniques'])} techniques; no ransomware.live calls")
    except (OSError, ValueError, requests.RequestException) as error:
        print(f"::warning::ATT&CK guidance unavailable: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
