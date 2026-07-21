"""Argument parsing and the ``main()`` entry point (``python -m swiftioc``)."""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from . import http_client
from .collect import collect_from_yaml, parse_name_int_pairs, top_tags, type_breakdown
from .http_client import UA_POOL, get_fetch_metrics, logger
from .logging_utils import configure_logging
from .models import classify, defang_min, iso, now_utc, parse_dt
from .scoring import (
    apply_retention,
    compute_score,
    high_confidence_rows,
    load_previous_feed,
    merge_with_previous,
    source_count,
)
from .writers import (
    write_badge_json,
    write_changelog,
    write_csv,
    write_dashboard_feed,
    write_history,
    write_json,
    write_jsonl,
    write_misp_feed,
    write_rss_feed,
    write_stix,
    write_tsv,
)


def _load_ua_file(path: Optional[Path]) -> None:
    if not path:
        return
    if not path.exists():
        logger.warning("UA file not found: %s", path)
        return
    try:
        pool = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
        if pool:
            UA_POOL.clear()
            UA_POOL.extend(pool)
            logger.info("Loaded %d User-Agents from %s", len(pool), path)
    except Exception as e:
        logger.warning("Failed loading UA file: %s", e)


# ---------------- small helpers ----------------
def gh_summary_path() -> Optional[Path]:
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(p) if p else None


def append_gh_summary(lines: List[str]) -> None:
    p = gh_summary_path()
    if not p:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


def _self_tests() -> int:
    assert classify("1.2.3.4") == "ipv4"
    assert classify("2001:db8::1") == "ipv6"
    assert classify("https://x.com") == "url"
    assert classify("example.com") == "domain"
    assert classify("CVE-2025-12345") == "cve"
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    df = defang_min("https://a.b")
    assert df.startswith("hxxps://") and "[.]" in df
    print("Self-tests passed.")
    return 0


# ---------------- CLI ----------------
def main() -> int:
    ap = argparse.ArgumentParser(description="SwiftIOC — collect IOCs from YAML-defined sources (CI-friendly)")
    ap.add_argument("--out-dir", type=Path, default=Path("public"))
    ap.add_argument("--sources", type=Path, default=Path("sources.yml"))
    ap.add_argument("--window-hours", type=int, default=48)
    ap.add_argument("--skip-rss", action="store_true")
    ap.add_argument("--max-per-source", type=int, default=None)
    ap.add_argument("--max-workers", type=int, default=8, help="Concurrent source fetches (1 disables threading)")
    ap.add_argument("--no-fp-filter", dest="fp_filter", action="store_false", help="Disable bogon / false-positive filtering")
    ap.set_defaults(fp_filter=True)
    ap.add_argument("--persist-feed", action="store_true",
                    help="Living feed: merge the previously published latest.jsonl, decay scores by age, expire stale entries")
    ap.add_argument("--min-score", type=int, default=20,
                    help="Expire indicators whose decayed score falls below this (default 20)")
    ap.add_argument("--max-age-days", type=int, default=None,
                    help="Retention: drop indicators whose last_seen is older than N days")
    ap.add_argument("--max-store", type=int, default=None,
                    help="Retention: keep only the top N indicators by score/recency (KEVIntel-style curation)")
    ap.add_argument("--dashboard-rows", type=int, default=1000,
                    help="Rows in the compact dashboard.jsonl the web dashboard downloads (default 1000)")
    ap.add_argument("--site-url", type=str,
                    default="https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector",
                    help="Public site URL used as the <link> in the RSS feed (override for forks/custom domains)")
    ap.add_argument("--rss-limit", type=int, default=50, help="Number of items in feed.xml (default 50)")
    ap.add_argument("--no-misp-feed", dest="misp_feed", action="store_false", help="Disable writing the MISP feed directory")
    ap.set_defaults(misp_feed=True)
    ap.add_argument("--high-confidence-score", type=int, default=80,
                    help="Score at/above which an indicator enters the curated high_confidence feed (default 80)")
    ap.add_argument("--urlhaus-status", choices=["any", "online", "offline"], default="any")
    ap.add_argument("--source-window", action="append", default=[], help="Override lookback per source: name=HOURS")
    ap.add_argument("--fail-on-empty", nargs="*", default=None, help="Fail if any listed sources return zero")
    ap.add_argument("--fail-if-stale", action="append", default=[], help="Fail if source newest first_seen older than HOURS: name=HOURS")
    ap.add_argument("--grace-on-404", action="append", default=[], help="Treat 404 on these sources as empty but non-fatal: name")

    # logging / diag
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--log-file", type=Path, default=None)
    ap.add_argument("--log-format", choices=["text", "json"], default="text")
    ap.add_argument("--log-file-level", choices=["ERROR", "WARNING", "INFO", "DEBUG"], default="DEBUG")
    ap.add_argument("--save-raw-dir", type=Path, default=None)
    # Default to None so unset paths can follow --out-dir instead of always
    # landing in ./public (which silently wrote into the repo when running
    # with a custom --out-dir).
    ap.add_argument("--diag-json", type=Path, default=None, help="Diagnostics JSON path (default: <out-dir>/diagnostics/run.json)")
    ap.add_argument("--report", type=Path, default=None, help="Markdown run report path (default: <out-dir>/diagnostics/REPORT.md)")
    ap.add_argument("--ua-file", type=Path, default=None, help="Optional file with one UA per line")

    # CI helpers
    ap.add_argument("--ci-safe", action="store_true", help="CI convenience: JSON logs, ensure diagnostics dirs, tolerate missing RSS dep")

    ap.add_argument("--self-test", action="store_true")

    args = ap.parse_args()

    if args.self_test:
        return _self_tests()

    # CI-aware tweaks
    on_ci = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    if args.ci_safe:
        args.log_format = "json"
        if not args.save_raw_dir:
            args.save_raw_dir = Path("public/diagnostics/raw")
        # RSS still runs; fetch_rss tolerates a missing feedparser dependency.
    if on_ci and args.verbose == 0:
        # default to INFO on CI to get more signal in logs
        args.verbose = 1

    # logging
    console_level = logging.WARNING
    if args.verbose == 1:
        console_level = logging.INFO
    elif args.verbose >= 2:
        console_level = logging.DEBUG
    file_level = getattr(logging, args.log_file_level, logging.DEBUG) if isinstance(args.log_file_level, str) else logging.DEBUG
    configure_logging(console_level, log_file=args.log_file, file_level=file_level, fmt=args.log_format)

    # Set on the http_client module itself (not a local rebind): http_get()/
    # save_raw() read these as http_client's own globals, so assigning a
    # same-named local in cli.py would silently decouple from what they see.
    http_client._SAVE_RAW_DIR = args.save_raw_dir
    http_client.HTTP_DEBUG = (console_level == logging.DEBUG or file_level == logging.DEBUG)

    # UA file
    _load_ua_file(args.ua_file)

    # Derive unset diagnostics paths from --out-dir, then ensure the dirs
    # exist (nice for GH Artifacts).
    if args.diag_json is None:
        args.diag_json = args.out_dir / "diagnostics" / "run.json"
    if args.report is None:
        args.report = args.out_dir / "diagnostics" / "REPORT.md"
    args.diag_json.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    if args.save_raw_dir:
        args.save_raw_dir.mkdir(parents=True, exist_ok=True)

    # YAML (auto fallback to example)
    if not args.sources.exists():
        ex = Path("sources.example.yml")
        if ex.exists():
            logger.warning("Sources file %s not found; using %s", args.sources, ex)
            args.sources = ex
        else:
            logger.error("Sources file not found: %s", args.sources)
            return 1
    with args.sources.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    # collect
    rows, counts, stats = collect_from_yaml(
        cfg,
        window_hours=args.window_hours,
        skip_rss=args.skip_rss,
        max_per_source=args.max_per_source,
        urlhaus_status=args.urlhaus_status,
        source_window=parse_name_int_pairs(args.source_window, "--source-window"),
        grace_on_404=set(args.grace_on_404 or []),
        ci_safe_rss=args.ci_safe,
        max_workers=args.max_workers,
        fp_filter=args.fp_filter,
    )
    # Snapshot the post-dedup, pre-persist/expiry/retention count: rows is
    # about to be grown (carried-forward indicators) and shrunk (expiry,
    # retention) below, and duplicates_removed must reflect cross-source
    # dedup alone, not get conflated with those later mutations.
    deduped_count = len(rows)

    out_dir: Path = args.out_dir

    # Living feed: merge the previously published feed so indicators persist
    # across runs. Re-observed entries refresh (score resets to full); entries
    # no longer being reported decay by age until they expire below --min-score.
    carried_forward = 0
    if args.persist_feed:
        previous = load_previous_feed(out_dir / "iocs" / "latest.jsonl")
        rows, carried_forward = merge_with_previous(rows, previous)
        logger.info("Persisted feed: carried forward %d indicators from previous run", carried_forward)

    score_now = now_utc()
    for r in rows:
        r.score = compute_score(r, score_now)
    before_expiry = len(rows)
    rows = [r for r in rows if r.score >= args.min_score]
    expired = before_expiry - len(rows)
    if expired:
        logger.info("Expired %d indicators below score threshold %d", expired, args.min_score)

    # Retention — keep the stored feed to the most recent + highest-signal
    # indicators ("top IOCs", KEVIntel-style). Applied here, before writing,
    # so the persisted latest.jsonl stays bounded run over run instead of
    # growing without limit.
    rows, aged_out, pruned_over_cap = apply_retention(
        rows, max_age_days=args.max_age_days, max_store=args.max_store, now=score_now
    )
    if aged_out:
        logger.info("Aged out %d indicators last seen over %d days ago", aged_out, args.max_age_days)
    if pruned_over_cap:
        logger.info("Retained top %d indicators (pruned %d over --max-store)", args.max_store, pruned_over_cap)

    # outputs
    write_csv(out_dir / "iocs" / "latest.csv", rows)
    write_tsv(out_dir / "iocs" / "latest.tsv", rows)
    write_json(out_dir / "iocs" / "latest.json", rows)
    write_jsonl(out_dir / "iocs" / "latest.jsonl", rows)
    write_stix(out_dir / "iocs" / "stix2.json", rows)

    # Curated "block-ready" feed: only high-score or multi-source-confirmed
    # indicators, sorted strongest-first so the top of the file is the most
    # dangerous. Compact, so it is committed to git for direct raw-URL use.
    high_conf = sorted(
        high_confidence_rows(rows, min_score=args.high_confidence_score),
        key=lambda r: (-r.score, -source_count(r), r.type, r.indicator),
    )
    write_csv(out_dir / "iocs" / "high_confidence.csv", high_conf)
    write_jsonl(out_dir / "iocs" / "high_confidence.jsonl", high_conf)
    logger.info(
        "High-confidence feed: %d of %d indicators (score>=%d or 2+ sources)",
        len(high_conf), len(rows), args.high_confidence_score,
    )

    dashboard_written = write_dashboard_feed(
        out_dir / "iocs" / "dashboard.jsonl", rows, limit=args.dashboard_rows
    )
    logger.info("Dashboard feed: top %d rows written", dashboard_written)

    run_ts = iso(now_utc())

    if args.misp_feed:
        misp_count = write_misp_feed(out_dir / "misp", high_conf, run_ts=run_ts)
        logger.info("MISP feed: %d attributes in %s/misp", misp_count, out_dir)

    rss_written = write_rss_feed(
        out_dir / "feed.xml", high_conf, site_url=args.site_url, limit=args.rss_limit
    )
    logger.info("RSS feed: %d items written", rss_written)

    write_badge_json(out_dir / "badge.json", total=len(rows), generated=run_ts)

    write_history(
        out_dir / "diagnostics" / "history.json",
        {
            "ts": run_ts,
            "total": len(rows),
            "high_confidence": len(high_conf),
            "score_avg": round(sum(r.score for r in rows) / len(rows), 1) if rows else None,
        },
    )

    write_changelog(out_dir / "changelog" / "CHANGELOG.md", counts, total=len(rows))

    # diagnostics / summary
    type_totals = type_breakdown(rows)
    first_seen_dates: List[datetime] = []
    for r in rows:
        dt = parse_dt(r.first_seen)
        if dt:
            first_seen_dates.append(dt)
    earliest = iso(min(first_seen_dates)) if first_seen_dates else None
    latest = iso(max(first_seen_dates)) if first_seen_dates else None
    raw_total = stats.get("raw_total", deduped_count)
    duplicates_removed = max(raw_total - deduped_count, 0)
    empty_sources = sorted([name for name, count in counts.items() if count == 0])
    scores = [r.score for r in rows]
    # Full-feed aggregates the dashboard renders without downloading the whole
    # feed: score bands, corroboration count, and top tags.
    score_bands = {
        "critical": sum(1 for s in scores if s >= 80),
        "high": sum(1 for s in scores if 60 <= s < 80),
        "medium": sum(1 for s in scores if 40 <= s < 60),
        "low": sum(1 for s in scores if s < 40),
    }
    corroborated_total = sum(1 for r in rows if source_count(r) >= 2)
    # Per-source contribution to the STORED feed (post-dedup/expiry/retention),
    # so the dashboard's "Sources" table reflects what actually shipped rather
    # than raw pre-dedup fetch counts (which could show a single source at
    # 15,000 inside a 10,000-row feed). A merged multi-source row counts once
    # per contributing source.
    stored_counts: Dict[str, int] = {}
    for r in rows:
        for s in (p.strip() for p in r.source.split(",")):
            if s:
                stored_counts[s] = stored_counts.get(s, 0) + 1
    stored_counts = dict(sorted(stored_counts.items(), key=lambda kv: kv[1], reverse=True))
    diag = {
        "window_hours": args.window_hours,
        "total": len(rows),
        "total_before_dedup": raw_total,
        "duplicates_removed": duplicates_removed,
        "false_positives_removed": stats.get("false_positives_removed", 0),
        "persist_feed": bool(args.persist_feed),
        "carried_forward": carried_forward,
        "expired_low_score": expired,
        "aged_out": aged_out,
        "pruned_over_cap": pruned_over_cap,
        "stored": len(rows),
        "max_age_days": args.max_age_days,
        "max_store": args.max_store,
        "score_min": min(scores) if scores else None,
        "score_avg": round(sum(scores) / len(scores), 1) if scores else None,
        "score_max": max(scores) if scores else None,
        "score_bands": score_bands,
        "corroborated_total": corroborated_total,
        "high_confidence_total": len(high_conf),
        "high_confidence_score": args.high_confidence_score,
        "counts": counts,
        "stored_counts": stored_counts,
        "type_counts": {k: v for k, v in type_totals},
        "tag_counts": {k: v for k, v in top_tags(rows, 25)},
        "fetch_metrics": get_fetch_metrics(),
        "earliest_first_seen": earliest,
        "newest_first_seen": latest,
        "empty_sources": empty_sources,
        "failures": stats.get("failures", []),
        "version": 3,
        "ts": run_ts,
    }
    if args.diag_json:
        args.diag_json.write_text(json.dumps(diag, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.report:
        report_lines: List[str] = [
            "# SwiftIOC Run Report",
            "",
            "## Overview",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Generated | {run_ts} |",
            f"| Window (hours) | {args.window_hours} |",
            f"| Total indicators | {len(rows)} |",
            f"| Duplicates removed | {duplicates_removed} |",
        ]
        if args.persist_feed:
            report_lines.append(f"| Carried forward | {carried_forward} |")
            report_lines.append(f"| Expired (score < {args.min_score}) | {expired} |")
        if args.max_age_days is not None:
            report_lines.append(f"| Aged out (> {args.max_age_days}d) | {aged_out} |")
        if args.max_store is not None:
            report_lines.append(f"| Pruned over cap ({args.max_store}) | {pruned_over_cap} |")
            report_lines.append(f"| Stored | {len(rows)} |")
        if scores:
            report_lines.append(f"| Score (min / avg / max) | {min(scores)} / {round(sum(scores) / len(scores), 1)} / {max(scores)} |")
        report_lines.append(f"| High-confidence indicators | {len(high_conf)} |")
        if earliest:
            report_lines.append(f"| Earliest first_seen | {earliest} |")
        if latest:
            report_lines.append(f"| Newest first_seen | {latest} |")
        report_lines.append("")
        report_lines.extend(["## Per-source counts", ""])
        report_lines.append("| Source | Indicators |")
        report_lines.append("| --- | ---: |")
        if counts:
            for name, count in sorted(counts.items()):
                report_lines.append(f"| {name} | {count} |")
        else:
            report_lines.append("| _None_ | 0 |")
        report_lines.append("")
        if type_totals:
            report_lines.extend(["## Indicator types", "", "| Type | Indicators |", "| --- | ---: |"])
            for t, count in type_totals:
                report_lines.append(f"| {t} | {count} |")
            report_lines.append("")
        issues: List[str] = []
        for failure in stats.get("failures", []):
            src = failure.get("source", "unknown")
            err = failure.get("error", "")
            issues.append(f"- ⚠️ **{src}**: {err}")
        for src in empty_sources:
            issues.append(f"- ⚠️ **{src}** returned zero indicators")
        if issues:
            report_lines.extend(["## Issues", "", *issues, ""])
        args.report.write_text("\n".join(report_lines), encoding="utf-8")

    # Append a brief GH step summary (if available)
    summary_lines: List[str] = [
        "### SwiftIOC",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total indicators | {len(rows)} |",
        f"| Duplicates removed | {duplicates_removed} |",
    ]
    if earliest:
        summary_lines.append(f"| Earliest first_seen | {earliest} |")
    if latest:
        summary_lines.append(f"| Newest first_seen | {latest} |")
    summary_lines.extend([
        "",
        "#### Per-source counts",
        "",
        "| Source | Indicators |",
        "| --- | ---: |",
    ])
    if counts:
        for name, count in sorted(counts.items()):
            summary_lines.append(f"| {name} | {count} |")
    else:
        summary_lines.append("| _None_ | 0 |")
    if type_totals:
        summary_lines.extend([
            "",
            "#### Indicator types",
            "",
            "| Type | Indicators |",
            "| --- | ---: |",
        ])
        for t, count in type_totals:
            summary_lines.append(f"| {t} | {count} |")
    issues_summary: List[str] = []
    for failure in stats.get("failures", []):
        src = failure.get("source", "unknown")
        err = failure.get("error", "")
        issues_summary.append(f"- ⚠️ **{src}**: {err}")
    for src in empty_sources:
        issues_summary.append(f"- ⚠️ **{src}** returned zero indicators")
    if issues_summary:
        summary_lines.extend(["", "#### Issues", "", *issues_summary])
    summary_lines.append("")
    append_gh_summary(summary_lines)

    # guardrails
    if args.fail_on_empty:
        empty = [s for s in args.fail_on_empty if counts.get(s, 0) == 0]
        if empty:
            logger.error("Failing due to empty sources: %s", empty)
            return 1

    stale_cfg = parse_name_int_pairs(args.fail_if_stale, "--fail-if-stale")
    if stale_cfg:
        newest: Dict[str, Optional[datetime]] = {}
        for r in rows:
            dt = parse_dt(r.first_seen)
            if dt is None:
                continue
            cur = newest.get(r.source)
            if cur is None or dt > cur:
                newest[r.source] = dt
        too_old: List[str] = []
        now = now_utc()
        for name, hours in stale_cfg.items():
            limit = now - timedelta(hours=hours)
            n = newest.get(name)
            if n is None or n < limit:
                too_old.append(name)
        if too_old:
            logger.error("Failing due to stale sources: %s", too_old)
            return 1

    if args.skip_rss:
        logger.info("RSS skipped — install 'feedparser' to enable RSS")
    logger.info("Wrote %d indicators to %s/iocs", len(rows), out_dir)
    logger.info("Per-source counts: %s", dict(counts))
    return 0
