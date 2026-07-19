"""End-to-end tests for swiftioc.cli.main() — the function GitHub Actions
actually invokes every 4 hours.

Every other test in this suite calls individual parsers/writers directly;
none of them exercise argument parsing, diagnostics-path derivation, the
persist-feed/expiry/retention pipeline wiring, or the diagnostics JSON that
main() itself assembles. si.http_get is monkeypatched (as everywhere else in
this suite) so nothing touches the network.
"""
from __future__ import annotations

import json

import swiftioc as si


def _write_sources_yml(path):
    path.write_text(
        """
window_hours: 48
apis:
  - name: src_a
    kind: txt
    parse: blocklist_txt
    url: http://example.invalid/a.txt
    reference: http://example.invalid/a
  - name: src_b
    kind: txt
    parse: blocklist_txt
    url: http://example.invalid/b.txt
    reference: http://example.invalid/b
""",
        encoding="utf-8",
    )


def _fake_http_get(url, *, name, **kwargs):
    # src_a: 3 unique entries. src_b: the same first two -> 2 genuine
    # cross-source duplicates once merged (5 raw rows -> 3 unique).
    if name == "src_a":
        return "1.1.1.1\n2.2.2.2\n3.3.3.3\n"
    if name == "src_b":
        return "1.1.1.1\n2.2.2.2\n"
    raise AssertionError(f"unexpected source {name!r}")


def _run_main(monkeypatch, argv):
    monkeypatch.setattr("sys.argv", argv)
    return si.main()


def test_cli_main_end_to_end_writes_expected_outputs(tmp_path, monkeypatch):
    sources = tmp_path / "sources.yml"
    _write_sources_yml(sources)
    out_dir = tmp_path / "out"
    monkeypatch.setattr(si, "http_get", _fake_http_get)

    rc = _run_main(
        monkeypatch,
        [
            "swiftioc",
            "--sources", str(sources),
            "--out-dir", str(out_dir),
            "--skip-rss",
        ],
    )
    assert rc == 0

    for rel in [
        "iocs/latest.csv", "iocs/latest.tsv", "iocs/latest.json", "iocs/latest.jsonl",
        "iocs/stix2.json", "iocs/high_confidence.csv", "iocs/high_confidence.jsonl",
        "iocs/dashboard.jsonl", "badge.json", "diagnostics/run.json", "diagnostics/REPORT.md",
        "changelog/CHANGELOG.md",
    ]:
        assert (out_dir / rel).exists(), f"missing output: {rel}"

    diag = json.loads((out_dir / "diagnostics" / "run.json").read_text(encoding="utf-8"))
    assert diag["total_before_dedup"] == 5
    # 5 raw rows (3 from src_a, 2 from src_b, both overlapping src_a's first
    # two) dedup to 3 unique indicators -> 2 genuine duplicates removed.
    assert diag["duplicates_removed"] == 2
    assert diag["counts"] == {"src_a": 3, "src_b": 2}
    assert "score_bands" in diag and "fetch_metrics" in diag

    rows = [json.loads(line) for line in (out_dir / "iocs" / "latest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {r["indicator"] for r in rows} == {"1[.]1[.]1[.]1", "2[.]2[.]2[.]2", "3[.]3[.]3[.]3"}


def test_cli_main_self_test_flag(monkeypatch, capsys):
    rc = _run_main(monkeypatch, ["swiftioc", "--self-test"])
    assert rc == 0
    assert "Self-tests passed" in capsys.readouterr().out


def test_cli_main_duplicates_removed_not_conflated_with_persist_feed_growth(tmp_path, monkeypatch):
    """Regression: duplicates_removed used to be computed from `rows` AFTER
    the --persist-feed merge grew it with carried-forward indicators, so
    real cross-source duplicate counts were silently wrong (even clamped to
    0 via max(...,0) when carry-forward growth outpaced raw_total).
    """
    sources = tmp_path / "sources.yml"
    _write_sources_yml(sources)
    out_dir = tmp_path / "out"
    monkeypatch.setattr(si, "http_get", _fake_http_get)

    # Seed a previous latest.jsonl with 10 indicators this run's raw fetch
    # never mentions, so --persist-feed carries all 10 forward and grows
    # `rows` well past this run's raw_total of 5.
    iocs_dir = out_dir / "iocs"
    iocs_dir.mkdir(parents=True)
    now = si.now_utc()
    with (iocs_dir / "latest.jsonl").open("w", encoding="utf-8") as f:
        for i in range(10):
            row = si.Indicator(
                indicator=f"9.9.9.{i}", type="ipv4", source="old_source",
                first_seen=si.iso(now), last_seen=si.iso(now),
                confidence="medium", tlp="CLEAR", tags="", reference="", context="",
                score=60, sightings=1,
            )
            f.write(json.dumps(vars(row)) + "\n")

    rc = _run_main(
        monkeypatch,
        [
            "swiftioc",
            "--sources", str(sources),
            "--out-dir", str(out_dir),
            "--skip-rss",
            "--persist-feed",
            "--min-score", "1",
        ],
    )
    assert rc == 0

    diag = json.loads((out_dir / "diagnostics" / "run.json").read_text(encoding="utf-8"))
    # Post-merge row count is 3 (this run's unique) + 10 (carried forward)
    # = 13, comfortably past raw_total (5) — the old buggy computation
    # (raw_total - len(rows), clamped to 0) would report 0 here.
    assert diag["total_before_dedup"] == 5
    assert diag["duplicates_removed"] == 2
    assert diag["total"] == 13
