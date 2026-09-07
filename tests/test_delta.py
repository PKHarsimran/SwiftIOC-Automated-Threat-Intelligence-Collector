from __future__ import annotations

import json

import swiftioc as si


def indicator(value: str, *, score: int = 80, source: str = "feed-a", tags: str = "c2") -> si.Indicator:
    return si.Indicator(
        indicator=value, type="domain", source=source,
        first_seen="2026-09-01T00:00:00Z", last_seen="2026-09-08T00:00:00Z",
        confidence="high", score=score, sightings=1, tlp="CLEAR", tags=tags,
        reference="https://example.invalid", context="test",
    )


def test_delta_reports_additions_material_updates_and_removals(tmp_path):
    previous = [
        indicator("removed.example"),
        indicator("changed.example", score=79),
        indicator("decayed.example", score=70),
    ]
    current = [
        indicator("added.example"),
        indicator("changed.example", score=80, source="feed-a,feed-b"),
        indicator("decayed.example", score=68),
    ]
    delta = si.build_delta(
        previous, current, generated_at="2026-09-08T04:00:00Z",
        previous_generated_at="2026-09-08T00:00:00Z",
    )
    assert delta["counts"] == {"added": 1, "updated": 1, "removed": 1}
    assert [event["action"] for event in delta["events"]] == [
        "added", "updated", "removed_from_feed",
    ]
    updated = delta["events"][1]
    assert updated["changes"]["score"] == {"from": 79, "to": 80}
    assert "source" in updated["changes"]

    si.write_delta(tmp_path / "delta.json", tmp_path / "delta.jsonl", delta)
    assert json.loads((tmp_path / "delta.json").read_text())["counts"] == delta["counts"]
    lines = (tmp_path / "delta.jsonl").read_text().splitlines()
    assert [json.loads(line)["action"] for line in lines] == [
        "added", "updated", "removed_from_feed",
    ]


def test_delta_without_baseline_does_not_flood_first_run():
    delta = si.build_delta(
        [], [indicator("first.example")], generated_at="2026-09-08T00:00:00Z",
        baseline_available=False,
    )
    assert delta["events"] == []
    assert delta["counts"] == {"added": 0, "updated": 0, "removed": 0}


def test_carried_forward_rescoring_does_not_mutate_delta_baseline():
    previous = indicator("decaying.example", score=65)
    merged, carried = si.merge_with_previous([], [previous])
    assert carried == 1
    assert merged[0] is not previous
    merged[0].score = 59
    delta = si.build_delta(
        [previous], merged, generated_at="2026-09-08T04:00:00Z"
    )
    assert previous.score == 65
    assert delta["counts"] == {"added": 0, "updated": 1, "removed": 0}
    assert delta["events"][0]["changes"]["score"] == {"from": 65, "to": 59}
    removed = si.build_delta(
        [previous], [], generated_at="2026-09-08T08:00:00Z"
    )
    assert removed["events"][0]["previous"]["score"] == 65
