"""Relevance scoring, corroboration, retention, and living-feed merge."""
from __future__ import annotations

import json
from dataclasses import fields as dataclass_fields
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .fp import is_false_positive
from .models import Indicator, merge_conf, now_utc, parse_dt


# ---------------- scoring: corroboration + age decay ----------------
# Base score by source-assigned confidence.
SCORE_BASE = {"low": 40, "medium": 60, "high": 80}
# Each independent source beyond the first adds a corroboration bonus: an IP
# reported by Feodo *and* ThreatFox *and* a blog post is qualitatively
# different from a single scanner hit.
CORROBORATION_BONUS = 8
CORROBORATION_CAP = 16
# Exponential decay half-life per indicator type, in hours. Network
# infrastructure churns fast (a C2 IP from a month ago is likely someone
# else's VPS today); file hashes stay malicious essentially forever, so they
# decay slowly and CVEs slower still.
DECAY_HALF_LIFE_HOURS: Dict[str, float] = {
    "url": 24 * 7.0,
    "ipv4": 24 * 7.0,
    "ipv6": 24 * 7.0,
    "domain": 24 * 14.0,
    "ipv4_cidr": 24 * 30.0,
    "ipv6_cidr": 24 * 30.0,
    "ja3": 24 * 30.0,
    "ja3s": 24 * 30.0,
    "email": 24 * 30.0,
    "btc_address": 24 * 90.0,
    "md5": 24 * 180.0,
    "sha1": 24 * 180.0,
    "sha256": 24 * 180.0,
    "sha512": 24 * 180.0,
    "cve": 24 * 365.0,
}
DEFAULT_HALF_LIFE_HOURS = 24 * 14.0


def compute_score(indicator: Indicator, now: Optional[datetime] = None) -> int:
    """Score an indicator 0-100: confidence base + corroboration, decayed by age.

    Decay is exponential on hours since ``last_seen`` with a per-type
    half-life, so a freshly observed indicator keeps its full score and a
    stale one fades until it drops below the expiry threshold.
    """
    now = now or now_utc()
    base = SCORE_BASE.get(indicator.confidence, 50)
    n_sources = len([s for s in indicator.source.split(",") if s.strip()])
    bonus = min(max(n_sources - 1, 0) * CORROBORATION_BONUS, CORROBORATION_CAP)
    last = parse_dt(indicator.last_seen) or now
    age_hours = max((now - last).total_seconds() / 3600.0, 0.0)
    half_life = DECAY_HALF_LIFE_HOURS.get(indicator.type, DEFAULT_HALF_LIFE_HOURS)
    decay = 0.5 ** (age_hours / half_life)
    return max(0, min(100, round((base + bonus) * decay)))


def source_count(indicator: Indicator) -> int:
    """Number of independent feeds reporting this indicator."""
    return len([s for s in indicator.source.split(",") if s.strip()])


def high_confidence_rows(rows: List[Indicator], *, min_score: int = 80) -> List[Indicator]:
    """Curated subset safe to action directly.

    An indicator qualifies if it scores at or above ``min_score`` (fresh +
    confident) OR is corroborated by two or more independent sources. This is
    the "block-ready" feed: high-signal, low-false-positive.
    """
    return [r for r in rows if r.score >= min_score or source_count(r) >= 2]


def apply_retention(
    rows: List[Indicator],
    *,
    max_age_days: Optional[int] = None,
    max_store: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Tuple[List[Indicator], int, int]:
    """Curate the stored feed to the most recent + top-scoring indicators.

    This is the "top IOCs" retention (KEVIntel-style): first drop anything not
    seen within ``max_age_days``, then keep only the ``max_store`` strongest by
    (score, corroboration, recency). Returns ``(rows, aged_out, pruned)``.
    Both bounds are optional and off by default.
    """
    now = now or now_utc()
    aged_out = 0
    if max_age_days is not None:
        cutoff = now - timedelta(days=max_age_days)
        before = len(rows)
        rows = [r for r in rows if (parse_dt(r.last_seen) or now) >= cutoff]
        aged_out = before - len(rows)
    pruned = 0
    if max_store is not None and len(rows) > max_store:
        rows = sorted(
            rows,
            key=lambda r: (r.score, source_count(r), r.last_seen, r.indicator),
            reverse=True,
        )
        pruned = len(rows) - max_store
        rows = rows[:max_store]
    return rows, aged_out, pruned


def load_previous_feed(path: Path) -> List[Indicator]:
    """Load a previously published latest.jsonl so the feed can persist.

    Tolerant of missing files, malformed lines, and schema drift (unknown
    keys are ignored; rows missing required fields are skipped). Entries that
    the current false-positive rules would reject are dropped on load, so an
    improved FP list retroactively cleans the carried-forward feed.
    """
    if not path.exists():
        return []
    field_names = {f.name for f in dataclass_fields(Indicator)}
    out: List[Indicator] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        try:
            ind = Indicator(**{k: v for k, v in data.items() if k in field_names})
        except TypeError:
            continue
        if is_false_positive(ind.type, ind.indicator):
            continue
        out.append(ind)
    return out


def merge_with_previous(current: List[Indicator], previous: List[Indicator]) -> Tuple[List[Indicator], int]:
    """Merge the previous feed into this run's results ("living feed").

    Indicators re-observed this run keep their fresh ``last_seen`` (so their
    score resets to full) while inheriting the earliest ``first_seen``, the
    accumulated source/tag history, and an incremented ``sightings`` count.
    Indicators seen only previously are carried forward untouched — their
    stale ``last_seen`` makes the decay scoring fade them out until expiry.
    Returns (merged, carried_forward).
    """
    uniq: Dict[Tuple[str, str], Indicator] = {i.key(): i for i in current}
    carried = 0
    for prev in previous:
        k = prev.key()
        if k not in uniq:
            uniq[k] = prev
            carried += 1
            continue
        cur = uniq[k]
        p_first = parse_dt(prev.first_seen)
        c_first = parse_dt(cur.first_seen)
        if p_first and (c_first is None or p_first < c_first):
            cur.first_seen = prev.first_seen
        merged_tags = set(filter(None, cur.tags.split(","))) | set(filter(None, prev.tags.split(",")))
        cur.tags = ",".join(sorted(t for t in merged_tags if t))
        merged_sources = set(filter(None, cur.source.split(","))) | set(filter(None, prev.source.split(",")))
        cur.source = ",".join(sorted(merged_sources))
        cur.confidence = merge_conf(cur.confidence, prev.confidence)
        # Re-observed this run: one more sighting on top of the accumulated
        # history. max() guards against a malformed/reset previous count.
        cur.sightings = max(prev.sightings, 1) + 1
    merged = sorted(uniq.values(), key=lambda r: (r.type, r.indicator, r.source))
    return merged, carried

