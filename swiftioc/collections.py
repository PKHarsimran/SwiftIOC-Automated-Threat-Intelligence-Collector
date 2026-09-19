"""Separate actionable observables from per-CVE vulnerability evidence."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Indicator, normalize_value, now_utc, parse_dt
from .writers import write_json_document, write_jsonl


def vulnerability_records(rows: List[Indicator], *, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """One record per exact CVE identity, never per generic tag or provider."""
    records: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if row.type != "cve":
            continue
        cve_id = normalize_value("cve", row.indicator)
        record = records.setdefault(cve_id, {
            "cve_id": cve_id, "sources": [], "reports": {}, "tags": [],
            "description": row.context, "reference": row.reference,
        })
        record["sources"] = sorted(set(record["sources"]) | set(filter(None, row.source.split(","))))
        record["tags"] = sorted(set(record["tags"]) | set(filter(None, row.tags.split(","))))
        record["reports"].update(row.vulnerability)
    for record in records.values():
        reports = record["reports"]
        kev = reports.get("cisa_kev")
        nvd = reports.get("nvd")
        if isinstance(kev, dict) and kev:
            record["exploitation_status"] = "known_exploited"
            record["title"] = kev.get("title") or record["cve_id"]
        elif "exploited-in-the-wild" in record["tags"]:
            # Legacy feeds and third-party reports lack structured KEV evidence.
            record["exploitation_status"] = "reported_exploitation"
            record["title"] = record["cve_id"]
        else:
            record["exploitation_status"] = "not_established"
            record["title"] = record["cve_id"]
        if isinstance(nvd, dict) and nvd.get("description"):
            record["description"] = nvd["description"]
    priority = {"known_exploited": 0, "reported_exploitation": 1, "not_established": 2}
    cutoff = now or now_utc()

    def sort_key(record: Dict[str, Any]) -> tuple:
        kev = record["reports"].get("cisa_kev") or {}
        nvd = record["reports"].get("nvd") or {}
        kev = kev if isinstance(kev, dict) else {}
        nvd = nvd if isinstance(nvd, dict) else {}
        date = kev.get("date_added") if record["exploitation_status"] == "known_exploited" else nvd.get("published_at")
        parsed = parse_dt(date)
        newest = parsed.timestamp() if parsed and parsed <= cutoff else float("-inf")
        rejected = str(nvd.get("status") or "").strip().lower() == "rejected"
        return rejected, priority[record["exploitation_status"]], -newest, record["cve_id"]

    return sorted(records.values(), key=sort_key)


def write_collections(out_dir: Path, rows: List[Indicator], *, generated_at: str) -> Dict[str, int]:
    """Add typed exports while preserving the legacy combined feed contract."""
    vulnerabilities = vulnerability_records(rows, now=parse_dt(generated_at))
    observables = [row for row in rows if row.type != "cve"]
    counts = {
        "observables": len(observables), "vulnerabilities": len(vulnerabilities),
        "known_exploited": sum(r["exploitation_status"] == "known_exploited" for r in vulnerabilities),
        "reported_exploitation": sum(r["exploitation_status"] == "reported_exploitation" for r in vulnerabilities),
        "not_established": sum(r["exploitation_status"] == "not_established" for r in vulnerabilities),
    }
    write_jsonl(out_dir / "observables.jsonl", observables)
    write_json_document(out_dir / "vulnerabilities.json", {
        "schema_version": 1, "generated_at": generated_at,
        "scope": "Vulnerabilities in the retained feed; source windows, failures and retention may limit coverage.",
        "counts": counts, "items": vulnerabilities,
    })
    return counts
