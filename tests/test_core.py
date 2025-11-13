from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from swiftioc import Indicator, collect_from_yaml, register_parser
from swiftioc.core import classify, defang_min, iso, now_utc, parse_dt, type_counts


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1.2.3.4", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("https://example.com", "url"),
        ("example.com", "domain"),
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
        ("CVE-2023-12345", "cve"),
    ],
)
def test_classify_known_types(value: str, expected: str) -> None:
    assert classify(value) == expected


def test_defang_roundtrip() -> None:
    result = defang_min("https://evil.example.com")
    assert result.startswith("hxxps://")
    assert "[.]" in result


@register_parser("test_dedup")
def _test_parser(url: str, ref_url: str, source: str, ws: datetime) -> list[Indicator]:
    base = now_utc()
    recent = iso(base)
    older = iso(base - timedelta(hours=1))
    return [
        Indicator(
            indicator="evil.example.com",
            type="domain",
            source=source,
            first_seen=recent,
            last_seen=recent,
            confidence="medium",
            tlp="CLEAR",
            tags="malware",
            reference=ref_url,
            context="First",
        ),
        Indicator(
            indicator="evil.example.com",
            type="domain",
            source=f"{source},external",
            first_seen=older,
            last_seen=older,
            confidence="high",
            tlp="CLEAR",
            tags="phishing",
            reference=ref_url,
            context="Second",
        ),
    ]


def test_collect_from_yaml_deduplicates_and_merges() -> None:
    config = {
        "apis": [
            {
                "name": "TestSource",
                "url": "https://example.invalid/api",
                "parse": "test_dedup",
                "reference": "https://example.invalid/reference",
            }
        ]
    }

    rows, counts, stats = collect_from_yaml(
        config,
        window_hours=48,
        skip_rss=True,
        max_per_source=None,
        urlhaus_status="any",
        source_window={},
        grace_on_404=set(),
        ci_safe_rss=False,
    )

    assert len(rows) == 1
    indicator = rows[0]
    assert indicator.indicator == "evil.example.com"
    assert indicator.confidence == "high"
    assert set(indicator.tags.split(",")) == {"malware", "phishing"}
    assert indicator.source == "TestSource,external"
    assert counts == {"TestSource": 2}
    assert stats["raw_total"] == 2
    assert type_counts(rows)["domain"] == 1


def test_parse_dt_handles_invalid_strings() -> None:
    assert parse_dt("not-a-date") is None
    assert parse_dt(None) is None


def test_iso_normalises_timezone() -> None:
    dt = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert iso(dt).endswith("Z")
