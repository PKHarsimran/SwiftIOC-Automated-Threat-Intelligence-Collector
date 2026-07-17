"""Orchestration: fan out to parsers concurrently, dedupe, and aggregate."""
from __future__ import annotations

import inspect
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .fp import is_false_positive
from .http_client import ensure_session, logger, reset_fetch_metrics
from .models import Indicator, iso, merge_conf, normalize_value, now_utc, parse_dt
from .parsers import fetch_rss, resolve_parser


# ---------------- collect / orchestrate ----------------
def parse_name_int_pairs(pairs: List[str], flag: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in pairs or []:
        if "=" in item:
            k, v = item.split("=", 1)
            try:
                out[k.strip()] = int(v.strip())
            except ValueError:
                logger.warning("Invalid %s pair: %s", flag, item)
    return out


def type_counts(items: List[Indicator]) -> Dict[str, int]:
    wanted = (
        "url",
        "domain",
        "ipv4",
        "ipv6",
        "ipv4_cidr",
        "ipv6_cidr",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "cve",
        "email",
        "btc_address",
        "ja3",
        "ja3s",
    )
    return {t: sum(1 for r in items if r.type == t) for t in wanted}


def type_breakdown(items: List[Indicator]) -> List[Tuple[str, int]]:
    bag: Dict[str, int] = {}
    for r in items:
        bag[r.type] = bag.get(r.type, 0) + 1
    return sorted(bag.items(), key=lambda kv: (-kv[1], kv[0]))


def top_tags(items: List[Indicator], n: int = 5) -> List[Tuple[str, int]]:
    bag: Dict[str, int] = {}
    for r in items:
        if not r.tags:
            continue
        for t in [x for x in r.tags.split(",") if x]:
            bag[t] = bag.get(t, 0) + 1
    return sorted(bag.items(), key=lambda kv: kv[1], reverse=True)[:n]


def collect_from_yaml(
    cfg: Dict[str, Any],
    window_hours: int,
    *,
    skip_rss: bool,
    max_per_source: Optional[int],
    urlhaus_status: str,
    source_window: Dict[str, int],
    grace_on_404: Set[str],
    ci_safe_rss: bool,
    max_workers: int = 8,
    fp_filter: bool = True,
) -> Tuple[List[Indicator], Dict[str, int], Dict[str, Any]]:
    base_start = now_utc() - timedelta(hours=window_hours)

    def start_for(name: str) -> datetime:
        if name in source_window:
            return now_utc() - timedelta(hours=source_window[name])
        return base_start

    def cap(xs: List[Indicator]) -> List[Indicator]:
        return xs[:max_per_source] if (max_per_source and len(xs) > max_per_source) else xs

    # Each source is fetched by a worker returning a result dict so the network
    # I/O can be run concurrently. Workers never raise: failures are captured in
    # the result so one bad feed cannot abort the whole run.
    def run_api(api: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = api.get("name", "api")
        parse = api.get("parse")
        if not parse:
            return None
        url = api.get("url", "")
        ref = api.get("reference", url) or ""
        ws = start_for(name)
        got: List[Indicator] = []
        options: Dict[str, Any] = {}
        failure: Optional[Dict[str, str]] = None
        try:
            t0 = time.perf_counter()
            parser_fn = resolve_parser(parse)
            parser_sig = inspect.signature(parser_fn)
            supported_kwargs = {
                k
                for k in parser_sig.parameters
                if k not in {"url", "ref_url", "source", "ws"}
            }

            options = dict(api.get("options", {}))
            for key in (
                "fallback_url",
                "graceful_404",
                "status_filter",
                "disable_window",
                "graceful_fail",
            ):
                if key in api and key not in options:
                    options[key] = api[key]

            if name in grace_on_404 and "graceful_404" in supported_kwargs:
                options.setdefault("graceful_404", True)

            if "status_filter" in supported_kwargs:
                options.setdefault("status_filter", urlhaus_status)

            filtered_options = {k: v for k, v in options.items() if k in supported_kwargs}
            got = parser_fn(url, ref, name, ws, **filtered_options)

            dt = time.perf_counter() - t0
            logger.debug("collect %s %d in %.2fs", name, len(got), dt)
            logger.debug("summary %s types=%s tags_top=%s", name, type_counts(got), top_tags(got))
        except Exception as e:
            graceful_fail = bool(api.get("graceful_fail") or options.get("graceful_fail"))
            logger.warning("%s failed: %s", name, e)
            if not graceful_fail:
                failure = {"source": name, "error": str(e)}
            got = []
        return {"name": name, "indicators": got, "failure": failure}

    def run_rss(rss: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = rss.get("name", "rss")
        url = rss.get("url")
        if not url:
            return None
        ref = rss.get("reference", url) or ""
        got: List[Indicator] = []
        failure: Optional[Dict[str, str]] = None
        try:
            t0 = time.perf_counter()
            got = fetch_rss(url, ref, name, start_for(name), tolerate_missing=ci_safe_rss)
            dt = time.perf_counter() - t0
            logger.debug("collect RSS %s %d in %.2fs", name, len(got), dt)
            logger.debug("summary %s types=%s tags_top=%s", name, type_counts(got), top_tags(got))
        except Exception as e:
            graceful_fail = bool(rss.get("graceful_fail"))
            logger.warning("%s failed: %s", name, e)
            if not graceful_fail:
                failure = {"source": name, "error": str(e)}
            got = []
        return {"name": name, "indicators": got, "failure": failure}

    # Build the ordered task list (APIs first, then RSS) so results stay
    # deterministic regardless of which worker finishes first.
    tasks: List[Tuple[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]], Dict[str, Any]]] = []
    for api in cfg.get("apis", []) or []:
        tasks.append((run_api, api))
    if not skip_rss:
        for rss in cfg.get("rss", []) or []:
            tasks.append((run_rss, rss))

    # Pre-initialise the shared HTTP session before fanning out so the workers
    # don't race on lazy creation. Reset telemetry so it reflects this run.
    ensure_session()
    reset_fetch_metrics()

    results: List[Optional[Dict[str, Any]]] = [None] * len(tasks)
    workers = max(1, min(max_workers, len(tasks))) if tasks else 1
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(fn, item): idx for idx, (fn, item) in enumerate(tasks)}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
    else:
        for idx, (fn, item) in enumerate(tasks):
            results[idx] = fn(item)

    indicators: List[Indicator] = []
    counts: Dict[str, int] = {}
    failures: List[Dict[str, str]] = []
    raw_total = 0
    fp_removed = 0
    for result in results:
        if result is None:
            continue
        if result["failure"]:
            failures.append(result["failure"])
        # Canonicalise host casing and drop bogon / benign false positives
        # *before* applying --max-per-source, so a cap doesn't get filled with
        # early junk rows while later, legitimate indicators are truncated away.
        kept: List[Indicator] = []
        for ind in result["indicators"]:
            ind.indicator = normalize_value(ind.type, ind.indicator)
            if fp_filter and is_false_positive(ind.type, ind.indicator):
                fp_removed += 1
                continue
            kept.append(ind)
        got = cap(kept)
        raw_total += len(got)
        indicators.extend(got)
        counts[result["name"]] = len(got)

    # Dedup + merge
    uniq: Dict[Tuple[str, str], Indicator] = {}
    for i in indicators:
        k = i.key()
        if k not in uniq:
            uniq[k] = i
            continue
        prev = uniq[k]
        # last_seen
        try:
            p = parse_dt(prev.last_seen) or now_utc()
            n = parse_dt(i.last_seen) or now_utc()
            prev.last_seen = iso(n if n > p else p)
        except Exception:
            prev.last_seen = max(prev.last_seen, i.last_seen)
        # confidence/tags/source merge
        prev.confidence = merge_conf(prev.confidence, i.confidence)
        merged_tags = set(filter(None, prev.tags.split(","))) | set(filter(None, i.tags.split(",")))
        prev.tags = ",".join(sorted(t.strip().strip('"') for t in merged_tags if t))
        if i.source not in prev.source.split(","):
            prev.source = ",".join(sorted(set(prev.source.split(",")) | set(i.source.split(","))))
    final = sorted(uniq.values(), key=lambda r: (r.type, r.indicator, r.source))
    stats: Dict[str, Any] = {
        "raw_total": raw_total,
        "failures": failures,
        "false_positives_removed": fp_removed,
    }
    return final, counts, stats


