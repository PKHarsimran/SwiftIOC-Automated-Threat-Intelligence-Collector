#!/usr/bin/env python3
"""Build an IOC "time machine" index from the git history of the published feed.

Every collection run commits ``public/iocs/latest.jsonl``, so the git history is
an append-only archive of *what the public threat landscape looked like at time
T, with what score, confirmed by which sources*. This walks that history and
answers the forensic question commercial platforms charge for:

    "Was this IP/domain publicly known-bad on the day we saw the traffic —
     and how confidently?"

Outputs:
  * <out-dir>/history/index.sqlite  — full per-indicator timeline (for the CLI
    ``ioc_timeline.py`` and any future lookup API). Large; git-ignored.
  * <out-dir>/history_summary.json  — compact per-indicator summary for ONLY
    the indicators in the current feed, small enough to commit and power the
    dashboard "dossier" panel.

Runs offline, stdlib only (sqlite3 + git via subprocess). Not part of the
4-hourly collect — run it locally or on a slower schedule.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

FEED_PATH = "public/iocs/latest.jsonl"
SCORE_SERIES_CAP = 200  # fallback cap when walking unbounded history (no --since-days)


def _run_git(args: List[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=True,
    )
    return result.stdout


def feed_commits(max_commits: Optional[int], since_days: Optional[int]) -> List[Tuple[str, int]]:
    """Return (commit_sha, unix_ts) for commits that touched the feed, oldest first."""
    args = ["log", "--format=%H %ct", "--reverse"]
    if since_days:
        args.append(f"--since={since_days} days ago")
    args += ["--", FEED_PATH]
    out = _run_git(args)
    commits: List[Tuple[str, int]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            commits.append((parts[0], int(parts[1])))
    if max_commits and len(commits) > max_commits:
        commits = commits[-max_commits:]  # keep the most recent N
    return commits


def feed_at_commit(sha: str) -> Iterable[dict]:
    """Yield indicator dicts from the feed as it was at ``sha`` (tolerant)."""
    try:
        blob = _run_git(["show", f"{sha}:{FEED_PATH}"])
    except subprocess.CalledProcessError:
        return
    for line in blob.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get("indicator"):
            yield row


def build(
    out_dir: Path,
    *,
    max_commits: Optional[int],
    since_days: Optional[int],
    summary_max: Optional[int] = 5000,
) -> Dict[str, int]:
    commits = feed_commits(max_commits, since_days)
    if not commits:
        raise SystemExit(f"No commits found touching {FEED_PATH}. Run from the repo root.")

    # A --since-days walk is already bounded, so cap the series at that many
    # points to keep the full configured window queryable via --at; without
    # --since-days the walk is unbounded (full repo history), so fall back to
    # SCORE_SERIES_CAP to keep the per-indicator blob from growing forever.
    series_cap = len(commits) if since_days else SCORE_SERIES_CAP

    hist_dir = out_dir / "history"
    hist_dir.mkdir(parents=True, exist_ok=True)
    db_path = hist_dir / "index.sqlite"
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(db_path)
    con.execute(
        """
        CREATE TABLE indicators (
            indicator TEXT NOT NULL,
            type TEXT NOT NULL,
            first_run_ts INTEGER NOT NULL,
            last_run_ts INTEGER NOT NULL,
            run_count INTEGER NOT NULL,
            max_score INTEGER NOT NULL,
            last_score INTEGER NOT NULL,
            last_sources TEXT,
            last_tags TEXT,
            score_series TEXT,
            PRIMARY KEY (type, indicator)
        )
        """
    )
    con.execute("CREATE TABLE runs (run_ts INTEGER PRIMARY KEY, total INTEGER NOT NULL)")

    # In-memory accumulation; feeds are bounded (top-N retention) so this fits.
    acc: Dict[Tuple[str, str], dict] = {}
    for sha, ts in commits:
        run_total = 0
        for row in feed_at_commit(sha):
            run_total += 1
            key = (str(row.get("type", "unknown")), str(row["indicator"]))
            score = int(row.get("score") or 0)
            entry = acc.get(key)
            if entry is None:
                acc[key] = {
                    "first_run_ts": ts,
                    "last_run_ts": ts,
                    "run_count": 1,
                    "max_score": score,
                    "last_score": score,
                    "last_sources": row.get("source", ""),
                    "last_tags": row.get("tags", ""),
                    "series": [(ts, score)],
                }
            else:
                entry["last_run_ts"] = ts
                entry["run_count"] += 1
                entry["max_score"] = max(entry["max_score"], score)
                entry["last_score"] = score
                entry["last_sources"] = row.get("source", "")
                entry["last_tags"] = row.get("tags", "")
                entry["series"].append((ts, score))
                if len(entry["series"]) > series_cap:
                    entry["series"] = entry["series"][-series_cap:]
        con.execute("INSERT OR REPLACE INTO runs VALUES (?, ?)", (ts, run_total))

    con.executemany(
        "INSERT INTO indicators VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            (
                ind, typ, e["first_run_ts"], e["last_run_ts"], e["run_count"],
                e["max_score"], e["last_score"], e["last_sources"], e["last_tags"],
                json.dumps(e["series"], separators=(",", ":")),
            )
            for (typ, ind), e in acc.items()
        ],
    )
    con.execute("CREATE INDEX idx_indicator ON indicators (indicator)")
    con.commit()

    # Compact summary for indicators in the CURRENT feed only (committable and
    # served to the dashboard). Cap to the most historically-attested
    # (highest run_count) so the file stays small — a giant blob would bloat
    # git and slow the dashboard lookup that fetches it.
    current = {(str(r.get("type", "unknown")), str(r["indicator"])) for r in feed_at_commit(commits[-1][0])}
    current_entries = [
        (ind, typ, e) for (typ, ind), e in acc.items() if (typ, ind) in current
    ]
    current_entries.sort(key=lambda t: (t[2]["run_count"], t[2]["max_score"]), reverse=True)
    if summary_max is not None:
        current_entries = current_entries[:summary_max]
    summary = {
        ind: {
            "type": typ,
            "first_seen_run": e["first_run_ts"],
            "last_seen_run": e["last_run_ts"],
            "run_count": e["run_count"],
            "max_score": e["max_score"],
        }
        for ind, typ, e in current_entries
    }
    (out_dir / "history_summary.json").write_text(
        json.dumps(summary, separators=(",", ":")), encoding="utf-8"
    )
    con.close()
    return {"commits": len(commits), "indicators": len(acc), "summary_entries": len(summary)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the SwiftIOC IOC history index from git.")
    ap.add_argument("--out-dir", type=Path, default=Path("public"))
    ap.add_argument("--max-commits", type=int, default=None, help="Only walk the most recent N feed commits")
    ap.add_argument("--since-days", type=int, default=None, help="Only walk commits from the last N days")
    ap.add_argument("--summary-max", type=int, default=5000,
                    help="Cap history_summary.json to the top N indicators by run_count (0 = no cap)")
    args = ap.parse_args()
    summary_max = args.summary_max if args.summary_max and args.summary_max > 0 else None
    stats = build(
        args.out_dir, max_commits=args.max_commits, since_days=args.since_days, summary_max=summary_max
    )
    print(
        f"Indexed {stats['indicators']:,} indicators across {stats['commits']:,} runs; "
        f"{stats['summary_entries']:,} in the current feed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
