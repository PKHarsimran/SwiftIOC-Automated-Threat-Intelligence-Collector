"""Tests for the IOC time-machine query tool (scripts/ioc_timeline.py).

Builds a small SQLite index matching the schema build_history_index.py emits,
then exercises the pure query/render logic — no git required.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from datetime import datetime
from pathlib import Path


def _load_timeline():
    path = Path(__file__).resolve().parent.parent / "scripts" / "ioc_timeline.py"
    spec = importlib.util.spec_from_file_location("ioc_timeline", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_index(tmp_path: Path, rows) -> Path:
    db = tmp_path / "index.sqlite"
    con = sqlite3.connect(db)
    con.execute(
        """CREATE TABLE indicators (
            indicator TEXT, type TEXT, first_run_ts INTEGER, last_run_ts INTEGER,
            run_count INTEGER, max_score INTEGER, last_score INTEGER,
            last_sources TEXT, last_tags TEXT, score_series TEXT,
            PRIMARY KEY (type, indicator))"""
    )
    con.executemany("INSERT INTO indicators VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
    con.commit()
    con.close()
    return db


def _ts(y, m, d):
    return int(datetime(y, m, d).timestamp())


def test_lookup_hit_and_miss(tmp_path):
    mod = _load_timeline()
    series = json.dumps([[_ts(2026, 1, 1), 60], [_ts(2026, 2, 1), 90]])
    db = _make_index(
        tmp_path,
        [("1.2.3.4", "ipv4", _ts(2026, 1, 1), _ts(2026, 2, 1), 20, 90, 90, "feodo,cins", "c2", series)],
    )
    hit = mod.lookup(db, "1.2.3.4")
    assert hit is not None and hit["run_count"] == 20 and hit["max_score"] == 90
    assert mod.lookup(db, "9.9.9.9") is None


def test_lookup_matches_defanged_or_raw(tmp_path):
    mod = _load_timeline()
    # Index stores the defanged form (as the feed does); a raw query must match.
    db = _make_index(
        tmp_path,
        [("evil[.]example[.]com", "domain", _ts(2026, 1, 1), _ts(2026, 2, 1), 3, 80, 80, "s", "t", "[]")],
    )
    assert mod.lookup(db, "evil.example.com") is not None


def test_render_point_in_time(tmp_path):
    mod = _load_timeline()
    series = [[_ts(2026, 2, 1), 70], [_ts(2026, 3, 1), 85]]
    row = {
        "indicator": "1.2.3.4", "type": "ipv4",
        "first_run_ts": _ts(2026, 2, 1), "last_run_ts": _ts(2026, 3, 1),
        "run_count": 10, "max_score": 85, "last_score": 85,
        "last_sources": "feodo", "last_tags": "c2",
        "score_series": json.dumps(series),
    }
    # Before it was first reported.
    out_before = mod.render(row, datetime(2026, 1, 15))
    assert "not yet reported" in out_before
    # While it was active.
    out_during = mod.render(row, datetime(2026, 2, 15))
    assert "present, score 70" in out_during


def test_render_at_treats_first_seen_day_as_present(tmp_path):
    """Regression: --at is a whole calendar day, not the 00:00 instant.

    If an indicator's very first sighting lands later the same day as the
    requested --at date (e.g. first observed 14:00 UTC), querying --at for
    that date must not report it as "not yet reported".
    """
    mod = _load_timeline()
    first_seen_ts = _ts(2026, 3, 1) + 14 * 3600  # 2026-03-01 14:00 UTC
    series = [[first_seen_ts, 70]]
    row = {
        "indicator": "1.2.3.4", "type": "ipv4",
        "first_run_ts": first_seen_ts, "last_run_ts": first_seen_ts,
        "run_count": 1, "max_score": 70, "last_score": 70,
        "last_sources": "feodo", "last_tags": "c2",
        "score_series": json.dumps(series),
    }
    out = mod.render(row, datetime(2026, 3, 1))
    assert "present, score 70" in out
    assert "not yet reported" not in out


def test_sparkline_bounds():
    mod = _load_timeline()
    assert mod._sparkline([]) == ""
    spark = mod._sparkline([(0, 40), (1, 60), (2, 100)])
    assert len(spark) == 3
    assert spark[0] == mod.SPARK[0]  # min maps to lowest block
    assert spark[-1] == mod.SPARK[-1]  # max maps to highest block
