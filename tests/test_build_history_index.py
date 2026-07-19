"""Tests for the history index builder (scripts/build_history_index.py).

Loads the script as a module and monkeypatches its git-shelling functions
(feed_commits/feed_at_commit) with synthetic data, so the sqlite-writing
logic can be exercised without a real git history.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path


def _load_builder():
    path = Path(__file__).resolve().parent.parent / "scripts" / "build_history_index.py"
    spec = importlib.util.spec_from_file_location("build_history_index", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_series_not_truncated_within_since_days_window(tmp_path, monkeypatch):
    """Regression: with --since-days set, the score series must cover the
    whole walked window, not be silently cut to the fixed fallback cap.
    """
    mod = _load_builder()
    n_commits = mod.SCORE_SERIES_CAP + 50  # exceed the old fixed cap
    commits = [(f"sha{i}", 1_700_000_000 + i * 14_400) for i in range(n_commits)]
    monkeypatch.setattr(mod, "feed_commits", lambda max_commits, since_days: commits)
    monkeypatch.setattr(
        mod, "feed_at_commit", lambda sha: iter([{"indicator": "1.2.3.4", "type": "ipv4", "score": 80, "source": "s", "tags": "t"}])
    )

    mod.build(tmp_path, max_commits=None, since_days=180)

    con = sqlite3.connect(tmp_path / "history" / "index.sqlite")
    row = con.execute("SELECT run_count, score_series FROM indicators WHERE indicator='1.2.3.4'").fetchone()
    con.close()
    run_count, score_series = row
    series = json.loads(score_series)
    assert run_count == n_commits
    assert len(series) == n_commits


def test_history_summary_keyed_by_type_and_indicator(tmp_path, monkeypatch):
    # Regression: history_summary.json used to be keyed by the bare
    # indicator string, so two indicators of different types sharing the
    # same string value would silently overwrite one another. Keying by
    # "type:indicator" (matching Indicator.key()'s convention) prevents that.
    mod = _load_builder()
    commits = [("sha0", 1_700_000_000)]
    monkeypatch.setattr(mod, "feed_commits", lambda max_commits, since_days: commits)
    monkeypatch.setattr(
        mod,
        "feed_at_commit",
        lambda sha: iter(
            [
                {"indicator": "COLLIDE", "type": "cve", "score": 80, "source": "s", "tags": "t"},
                {"indicator": "COLLIDE", "type": "domain", "score": 40, "source": "s", "tags": "t"},
            ]
        ),
    )

    mod.build(tmp_path, max_commits=None, since_days=180, summary_max=None)

    summary = json.loads((tmp_path / "history_summary.json").read_text(encoding="utf-8"))
    assert "cve:COLLIDE" in summary
    assert "domain:COLLIDE" in summary
    assert summary["cve:COLLIDE"]["max_score"] == 80
    assert summary["domain:COLLIDE"]["max_score"] == 40


def test_series_falls_back_to_fixed_cap_without_since_days(tmp_path, monkeypatch):
    """Without --since-days the walk is unbounded, so the series still needs
    a fixed ceiling to keep the per-indicator blob from growing forever.
    """
    mod = _load_builder()
    n_commits = mod.SCORE_SERIES_CAP + 50
    commits = [(f"sha{i}", 1_700_000_000 + i * 14_400) for i in range(n_commits)]
    monkeypatch.setattr(mod, "feed_commits", lambda max_commits, since_days: commits)
    monkeypatch.setattr(
        mod, "feed_at_commit", lambda sha: iter([{"indicator": "1.2.3.4", "type": "ipv4", "score": 80, "source": "s", "tags": "t"}])
    )

    mod.build(tmp_path, max_commits=None, since_days=None)

    con = sqlite3.connect(tmp_path / "history" / "index.sqlite")
    row = con.execute("SELECT run_count, score_series FROM indicators WHERE indicator='1.2.3.4'").fetchone()
    con.close()
    run_count, score_series = row
    series = json.loads(score_series)
    assert run_count == n_commits
    assert len(series) == mod.SCORE_SERIES_CAP
