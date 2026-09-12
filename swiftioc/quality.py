"""Evaluate collection requirements before replacing published intelligence."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from .models import parse_dt


def source_rule(value: str, maximum: int = 876000) -> Tuple[str, int]:
    name, separator, raw = value.partition('=')
    try:
        number = int(raw)
    except ValueError:
        number = 0
    if not separator or not name.strip() or not 0 < number <= maximum:
        raise argparse.ArgumentTypeError(f'Expected SOURCE=NUMBER with NUMBER 1–{maximum}.')
    return name.strip(), number


def publication_failures(
    counts: Dict[str, int],
    newest: Dict[str, str],
    previous_counts: Dict[str, int],
    *,
    required: List[str],
    stale: Dict[str, int],
    volume_drop: Dict[str, int],
    now: datetime,
) -> List[Dict[str, Any]]:
    failures: List[Dict[str, Any]] = []
    for name in required:
        if counts.get(name, 0) == 0:
            failures.append({'source': name, 'reason': 'empty', 'count': 0})
    for name, hours in stale.items():
        seen = parse_dt(newest.get(name))
        if seen is None or not now - timedelta(hours=hours) <= seen <= now:
            failures.append({'source': name, 'reason': 'stale', 'max_age_hours': hours,
                             'newest_first_seen': newest.get(name)})
    for name, threshold in volume_drop.items():
        if name not in counts:
            failures.append({'source': name, 'reason': 'missing_source'})
            continue
        previous = previous_counts.get(name, 0)
        if previous <= 0:
            continue  # No comparable baseline on the first successful run.
        current = counts.get(name, 0)
        # Compare before rounding so 49.96% cannot accidentally trip 50%.
        if (previous - current) * 100 >= previous * threshold:
            failures.append({'source': name, 'reason': 'volume_drop', 'previous': previous,
                             'current': current, 'threshold_percent': threshold,
                             'drop_percent': round((previous - current) * 100 / previous, 2)})
    return failures
