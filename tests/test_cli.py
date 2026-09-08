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
from typing import Any, Dict

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
        "iocs/delta.json", "iocs/delta.jsonl",
        "collections/observables.jsonl", "collections/vulnerabilities.json",
        "iocs/taxii2-envelope.json",
        "changelog/CHANGELOG.md",
        "detections/manifest.json", "detections/README.md",
        "detections/sigma/network-iocs.yml",
        "detections/suricata/swiftioc.rules", "detections/dns/swiftioc.rpz",
    ]:
        assert (out_dir / rel).exists(), f"missing output: {rel}"

    diag = json.loads((out_dir / "diagnostics" / "run.json").read_text(encoding="utf-8"))
    assert diag["collections"]["observables"] == 3
    assert diag["collections"]["vulnerabilities"] == 0
    assert diag["total_before_dedup"] == 5
    # 5 raw rows (3 from src_a, 2 from src_b, both overlapping src_a's first
    # two) dedup to 3 unique indicators -> 2 genuine duplicates removed.
    assert diag["duplicates_removed"] == 2
    assert diag["counts"] == {"src_a": 3, "src_b": 2}
    assert "score_bands" in diag and "fetch_metrics" in diag
    assert diag["delta_baseline_available"] is False
    assert diag["delta_counts"] == {"added": 0, "updated": 0, "removed": 0}
    assert diag["detection_pack"]["suricata_rules"] == 4

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


def test_cli_warns_on_large_source_volume_drop(tmp_path, monkeypatch):
    sources = tmp_path / "sources.yml"
    _write_sources_yml(sources)
    out_dir = tmp_path / "out"
    (out_dir / "diagnostics").mkdir(parents=True)
    (out_dir / "diagnostics" / "run.json").write_text(
        json.dumps({"counts": {"src_a": 10, "src_b": 2}}), encoding="utf-8"
    )
    monkeypatch.setattr(si, "http_get", _fake_http_get)
    rc = _run_main(monkeypatch, [
        "swiftioc", "--sources", str(sources), "--out-dir", str(out_dir), "--skip-rss",
        "--warn-if-volume-drop", "src_a=50",
    ])
    assert rc == 0
    diag = json.loads((out_dir / "diagnostics" / "run.json").read_text(encoding="utf-8"))
    assert diag["volume_drops"] == [{"source": "src_a", "previous": 10, "current": 3, "drop_percent": 70.0}]


def test_cli_delta_tracks_changes_between_published_runs(tmp_path, monkeypatch):
    sources = tmp_path / "sources.yml"
    _write_sources_yml(sources)
    out_dir = tmp_path / "out"
    monkeypatch.setattr(si, "http_get", _fake_http_get)
    assert _run_main(monkeypatch, [
        "swiftioc", "--sources", str(sources), "--out-dir", str(out_dir), "--skip-rss",
    ]) == 0

    def changed_feed(url, *, name, **kwargs):
        if name == "src_a":
            return "1.1.1.1\n4.4.4.4\n"
        if name == "src_b":
            return "1.1.1.1\n"
        raise AssertionError(name)

    monkeypatch.setattr(si, "http_get", changed_feed)
    assert _run_main(monkeypatch, [
        "swiftioc", "--sources", str(sources), "--out-dir", str(out_dir), "--skip-rss",
    ]) == 0
    delta = json.loads((out_dir / "iocs" / "delta.json").read_text())
    assert delta["baseline_available"] is True
    assert delta["counts"] == {"added": 1, "updated": 0, "removed": 2}
    assert {event["current"]["indicator"] for event in delta["events"] if event["action"] == "added"} == {
        "4[.]4[.]4[.]4"
    }


def test_cli_rejects_truncated_delta_baseline(tmp_path, monkeypatch):
    sources = tmp_path / "sources.yml"
    _write_sources_yml(sources)
    out_dir = tmp_path / "out"
    iocs = out_dir / "iocs"
    diagnostics = out_dir / "diagnostics"
    iocs.mkdir(parents=True)
    diagnostics.mkdir(parents=True)
    (iocs / "latest.jsonl").write_text('{"truncated":', encoding="utf-8")
    (diagnostics / "run.json").write_text(
        json.dumps({"total": 250, "counts": {}, "ts": "2026-09-08T00:00:00Z"}),
        encoding="utf-8",
    )
    monkeypatch.setattr(si, "http_get", _fake_http_get)
    assert _run_main(monkeypatch, [
        "swiftioc", "--sources", str(sources), "--out-dir", str(out_dir), "--skip-rss",
    ]) == 0
    delta = json.loads((iocs / "delta.json").read_text())
    assert delta["baseline_available"] is False
    assert delta["events"] == []
    assert delta["counts"] == {"added": 0, "updated": 0, "removed": 0}



def test_cli_retains_fresh_kev_before_higher_scoring_ioc_when_capped(tmp_path, monkeypatch):
    sources = tmp_path / "sources.yml"
    _write_sources_yml(sources)
    now = si.iso(si.now_utc())
    base: Dict[str, Any] = dict(first_seen=now, last_seen=now, confidence="high", tlp="CLEAR", tags="", reference="https://example.invalid", context="test")
    kev = si.Indicator(indicator="CVE-1900-1234", type="cve", source="kev", vulnerability={
        "cisa_kev": {"catalog_checked_at": now, "date_added": now}}, **base)
    ip = si.Indicator(indicator="8.8.8.8", type="ipv4", source="a,b,c", **base)
    monkeypatch.setattr("swiftioc.cli.collect_from_yaml", lambda *a, **kw: ([ip, kev], {"kev": 1, "a": 1}, {"raw_total": 2}))
    out_dir = tmp_path / "out"
    assert _run_main(monkeypatch, ["swiftioc", "--sources", str(sources), "--out-dir", str(out_dir), "--max-store", "1"]) == 0
    document = json.loads((out_dir / "collections/vulnerabilities.json").read_text())
    assert [r["cve_id"] for r in document["items"]] == ["CVE-1900-1234"]
    retained = json.loads((out_dir / "iocs/latest.jsonl").read_text())
    assert retained["type"] == "cve"
    assert (out_dir / "collections/observables.jsonl").read_text() == ""
