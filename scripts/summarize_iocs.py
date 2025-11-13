#!/usr/bin/env python3
"""Generate a concise Markdown summary for the latest SwiftIOC run."""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"


def to_int(value: Any) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO_FMT)


def load_diag(path: Path) -> Dict[str, Any] | None:
    if path and path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def load_iocs(path: Path) -> List[Dict[str, Any]]:
    if not path or not path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def to_table(rows: Sequence[Tuple[str, str]], headers: Tuple[str, str]) -> List[str]:
    if not rows:
        return ["_No data available._", ""]
    lines = [f"| {headers[0]} | {headers[1]} |", "| --- | ---: |"]
    lines.extend(f"| {k} | {v} |" for k, v in rows)
    lines.append("")
    return lines


def summarize_counts(counts: Dict[str, int], limit: int = 10) -> List[Tuple[str, int]]:
    if not counts:
        return []
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [(name, int(value)) for name, value in ordered]


def summarize_types(type_counts: Dict[str, int]) -> List[Tuple[str, int]]:
    return summarize_counts(type_counts)


def summarize_tags(rows: Iterable[Dict[str, Any]], limit: int = 10) -> List[Tuple[str, int]]:
    counter: Counter[str] = Counter()
    for row in rows:
        tags = (row.get("tags") or "").split(",")
        for tag in tags:
            tag = tag.strip()
            if tag:
                counter[tag] += 1
    ordered = counter.most_common(limit)
    return [(tag, int(count)) for tag, count in ordered]


def summarize_overlaps(
    rows: Iterable[Dict[str, Any]], limit: int | None = 10
) -> List[Dict[str, Any]]:
    overlaps: List[Dict[str, Any]] = []
    for row in rows:
        sources = [s.strip() for s in (row.get("source") or "").split(",") if s.strip()]
        if len(sources) <= 1:
            continue
        indicator = row.get("indicator") or "(unknown)"
        indicator_type = row.get("type") or "?"
        overlaps.append(
            {
                "indicator": str(indicator),
                "type": str(indicator_type),
                "sources": sorted(set(sources)),
            }
        )
    overlaps.sort(key=lambda item: (-len(item["sources"]), item["type"], item["indicator"]))
    if limit is None:
        return overlaps
    return overlaps[:limit]


def derive_counts(rows: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        sources = (row.get("source") or "").split(",")
        for src in sources:
            src = src.strip()
            if src:
                counts[src] += 1
    return dict(counts)


def derive_types(rows: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    for row in rows:
        typ = (row.get("type") or "").strip()
        if typ:
            counts[typ] += 1
    return dict(counts)


def derive_first_last(rows: Iterable[Dict[str, Any]]) -> Tuple[str | None, str | None]:
    first_seen: List[datetime] = []
    for row in rows:
        value = row.get("first_seen") or row.get("firstSeen")
        if not value:
            continue
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        first_seen.append(dt.astimezone(timezone.utc))
    if not first_seen:
        return None, None
    earliest = min(first_seen)
    latest = max(first_seen)
    return iso(earliest), iso(latest)


def build_highlights(
    diag: Dict[str, Any] | None, rows: List[Dict[str, Any]]
) -> Tuple[List[Tuple[str, str]], Dict[str, Any], List[Dict[str, Any]]]:
    total_value = diag.get("total") if diag else None
    total = to_int(total_value)
    if total is None:
        total = len(rows)
    duplicates_value = diag.get("duplicates_removed") if diag else None
    duplicates = to_int(duplicates_value) or 0
    generated_value = diag.get("ts") if diag else None
    if isinstance(generated_value, str) and generated_value:
        generated = generated_value
    elif generated_value:
        generated = str(generated_value)
    else:
        generated = iso(datetime.now(timezone.utc))
    window_value = diag.get("window_hours") if diag else None
    window = to_int(window_value) if window_value is not None else None
    counts = (diag.get("counts") if diag else None) or derive_counts(rows)
    active_sources = sum(1 for _, value in counts.items() if value > 0)
    type_counts = (diag.get("type_counts") if diag else None) or derive_types(rows)
    types_seen = len(type_counts)
    earliest = diag.get("earliest_first_seen") if diag else None
    newest = diag.get("newest_first_seen") if diag else None
    if not earliest or not newest:
        derived_first, derived_latest = derive_first_last(rows)
        earliest = earliest or derived_first
        newest = newest or derived_latest
    overlaps_all = summarize_overlaps(rows, limit=None)
    highlight_rows: List[Tuple[str, str]] = [("Generated", generated)]
    if window is not None:
        highlight_rows.append(("Window (hours)", str(window)))
    highlight_rows.append(("Total indicators", f"{total}"))
    highlight_rows.append(("Duplicates removed", f"{duplicates}"))
    highlight_rows.append(("Sources reporting", f"{active_sources}"))
    highlight_rows.append(("Indicator types", f"{types_seen}"))
    highlight_rows.append(("Multi-source overlaps", f"{len(overlaps_all)}"))
    if earliest:
        highlight_rows.append(("Earliest first_seen", earliest))
    if newest:
        highlight_rows.append(("Newest first_seen", newest))
    highlight_data: Dict[str, Any] = {
        "generated": generated,
        "window_hours": window,
        "total_indicators": total,
        "duplicates_removed": duplicates,
        "sources_reporting": active_sources,
        "indicator_types": types_seen,
        "multi_source_overlaps": len(overlaps_all),
        "earliest_first_seen": earliest,
        "newest_first_seen": newest,
    }
    return highlight_rows, highlight_data, overlaps_all


def render_summary(
    diag: Dict[str, Any] | None, rows: List[Dict[str, Any]]
) -> Tuple[str, str, str, Dict[str, Any]]:
    highlight_rows, highlight_data, _ = build_highlights(diag, rows)
    counts_raw = (diag.get("counts") if diag else None) or derive_counts(rows)
    counts = {str(k): to_int(v) or 0 for k, v in counts_raw.items()}
    type_counts_raw = (diag.get("type_counts") if diag else None) or derive_types(rows)
    type_counts = {str(k): to_int(v) or 0 for k, v in type_counts_raw.items()}
    top_sources = summarize_counts(counts)
    top_types = summarize_types(type_counts)
    tag_rows = summarize_tags(rows)
    overlap_rows = summarize_overlaps(rows)

    sections: List[str] = ["## Highlights", ""]
    sections.extend(to_table(highlight_rows, ("Metric", "Value")))

    sections.append("## Per-source totals")
    sections.append("")
    sections.extend(to_table(top_sources, ("Source", "Indicators")))

    sections.append("## Indicator types")
    sections.append("")
    sections.extend(to_table(top_types, ("Type", "Indicators")))

    sections.append("## Top tags")
    sections.append("")
    sections.extend(to_table(tag_rows, ("Tag", "Indicators")))

    sections.append("## Multi-source overlaps")
    sections.append("")
    if overlap_rows:
        sections.append("| Indicator | Sources |")
        sections.append("| --- | --- |")
        sections.extend(
            f"| {item['type']}: {item['indicator']} | {', '.join(item['sources'])} |"
            for item in overlap_rows
        )
        sections.append("")
    else:
        sections.append("_No overlapping indicators detected._")
        sections.append("")

    sections.append(
        "For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/)."
    )
    sections.append("")

    summary_body = "\n".join(sections)

    generated = diag.get("ts") if diag else iso(datetime.now(timezone.utc))
    summary_lines = ["# SwiftIOC IOC Summary", "", f"_Generated {generated}_", "", summary_body]
    summary_md = "\n".join(summary_lines)

    index_lines = [
        "# SwiftIOC Threat Intelligence Snapshot",
        "",
        "This site is generated automatically from the latest SwiftIOC collection run.",
        "",
        f"_Generated {generated}_",
        "",
        summary_body,
    ]
    index_md = "\n".join(index_lines)

    step_md = "## SwiftIOC IOC Summary\n\n" + summary_body
    summary_data: Dict[str, Any] = {
        **highlight_data,
        "counts": counts,
        "type_counts": type_counts,
        "top_sources": [{"source": name, "indicators": value} for name, value in top_sources],
        "top_indicator_types": [
            {"type": name, "indicators": value} for name, value in top_types
        ],
        "top_tags": [{"tag": tag, "indicators": count} for tag, count in tag_rows],
        "overlaps": [
            {
                "indicator": item["indicator"],
                "type": item["type"],
                "sources": item["sources"],
            }
            for item in summarize_overlaps(rows, limit=25)
        ],
    }
    return summary_md, index_md, step_md, summary_data


def write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_step_summary(content: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(content.strip() + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize SwiftIOC outputs into Markdown.")
    parser.add_argument("--diag", type=Path, default=Path("public/diagnostics/run.json"), help="Path to diagnostics JSON file")
    parser.add_argument("--ioc-jsonl", type=Path, default=Path("public/iocs/latest.jsonl"), help="Path to IOC JSONL export")
    parser.add_argument("--out", type=Path, default=Path("public/diagnostics/summary.md"), help="Output Markdown summary path")
    parser.add_argument("--index", type=Path, default=Path("public/index.md"), help="Output index Markdown path for GitHub Pages")
    parser.add_argument("--json", type=Path, default=None, help="Optional JSON summary path for dashboards")
    args = parser.parse_args()

    diag = load_diag(args.diag)
    rows = load_iocs(args.ioc_jsonl)

    summary_md, index_md, step_md, summary_data = render_summary(diag or {}, rows)
    write_output(args.out, summary_md)
    write_output(args.index, index_md)
    if args.json:
        write_json(args.json, summary_data)
    append_step_summary(step_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
