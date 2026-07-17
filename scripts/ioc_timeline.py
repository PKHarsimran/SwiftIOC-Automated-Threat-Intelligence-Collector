#!/usr/bin/env python3
"""Look up an indicator's history in the SwiftIOC time-machine index.

Answers, from free auditable public data: *was this IP/domain/URL/hash publicly
known-bad, when did it first appear, how did its score move, and which sources
confirmed it?* Build the index first with ``build_history_index.py``.

    python scripts/ioc_timeline.py 45.137.21.9
    python scripts/ioc_timeline.py --at 2026-03-01 evil.example.com
    python scripts/ioc_timeline.py --json 1.2.3.4
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

DEFAULT_DB = Path("public/history/index.sqlite")
SPARK = "▁▂▃▄▅▆▇█"


def _fmt_ts(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _refang(value: str) -> str:
    return (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
    )


def _defang(value: str) -> str:
    """Match how the feed stores network indicators (defang_min)."""
    return (
        value.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )


def _sparkline(series: List[Tuple[int, int]]) -> str:
    scores = [s for _, s in series]
    if not scores:
        return ""
    lo, hi = min(scores), max(scores)
    span = (hi - lo) or 1
    return "".join(SPARK[min(len(SPARK) - 1, int((s - lo) / span * (len(SPARK) - 1)))] for s in scores)


def lookup(db_path: Path, indicator: str) -> Optional[dict]:
    if not db_path.exists():
        raise SystemExit(f"Index not found at {db_path}. Run scripts/build_history_index.py first.")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    # The feed stores network indicators defanged (1[.]2[.]3[.]4); accept the
    # raw, refanged, or defanged form of whatever the user typed.
    variants = {indicator, _refang(indicator), _defang(indicator)}
    row = None
    for variant in variants:
        row = con.execute("SELECT * FROM indicators WHERE indicator = ?", (variant,)).fetchone()
        if row:
            break
    con.close()
    return dict(row) if row else None


def render(row: dict, at: Optional[datetime]) -> str:
    series = json.loads(row["score_series"] or "[]")
    lines = [
        f"Indicator : {row['indicator']}  ({row['type']})",
        f"Verdict   : ⚠ known-bad in the public feed across {row['run_count']:,} collection runs",
        f"First seen: {_fmt_ts(row['first_run_ts'])}",
        f"Last seen : {_fmt_ts(row['last_run_ts'])}",
        f"Score     : peak {row['max_score']}, latest {row['last_score']}  {_sparkline(series)}",
        f"Sources   : {row['last_sources'] or '—'}",
        f"Tags      : {row['last_tags'] or '—'}",
    ]
    if at is not None:
        # --at is a whole calendar day, not an instant: compare against the
        # end of that day so an indicator first seen later on the requested
        # date (e.g. first_run_ts at 14:00 UTC) still counts as present.
        at_start_ts = int(at.replace(tzinfo=timezone.utc).timestamp())
        at_end_ts = at_start_ts + 86399
        prior = [(ts, sc) for ts, sc in series if ts <= at_end_ts]
        if row["first_run_ts"] <= at_end_ts and at_start_ts <= row["last_run_ts"] and prior:
            lines.append(f"On {at.date()}: ✔ present, score {prior[-1][1]}")
        elif at_end_ts < row["first_run_ts"]:
            lines.append(f"On {at.date()}: ✘ not yet reported (first appeared {_fmt_ts(row['first_run_ts'])[:10]})")
        else:
            lines.append(f"On {at.date()}: ✘ not present in the feed at that time")
    return "\n".join(lines)


def _safe_print(text: str) -> None:
    """Print UTF-8, degrading to ASCII on consoles that can't encode it."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass
    try:
        print(text)
    except UnicodeEncodeError:
        ascii_map = str.maketrans({"⚠": "[!]", "✔": "[y]", "✘": "[n]", "✅": "[ok]", "—": "-"})
        text = text.translate(ascii_map)
        print("".join(c if ord(c) < 128 else "." for c in text))


def main() -> int:
    ap = argparse.ArgumentParser(description="Query the SwiftIOC IOC history index.")
    ap.add_argument("indicator", help="IP, domain, URL, or hash to look up")
    ap.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to index.sqlite")
    ap.add_argument("--at", type=str, default=None, help="Ask whether it was known-bad on this date (YYYY-MM-DD)")
    ap.add_argument("--json", action="store_true", help="Emit the raw record as JSON")
    args = ap.parse_args()

    row = lookup(args.db, args.indicator.strip())
    if not row:
        _safe_print(f"✅ {args.indicator}: never seen in the published feed history.")
        return 1

    if args.json:
        print(json.dumps(row, indent=2))
        return 0

    at = None
    if args.at:
        try:
            at = datetime.strptime(args.at, "%Y-%m-%d")
        except ValueError:
            print(f"Invalid --at date '{args.at}', expected YYYY-MM-DD", file=sys.stderr)
            return 2
    _safe_print(render(row, at))
    return 0


if __name__ == "__main__":
    sys.exit(main())
