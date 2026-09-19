import argparse
from datetime import datetime, timedelta, timezone

import pytest

from swiftioc.models import iso
from swiftioc.quality import publication_failures, source_rule


def test_threshold_rules_fail_closed_on_malformed_configuration():
    assert source_rule(' feed = 24 ') == ('feed', 24)
    for value in ['feed', '=24', 'feed=0', 'feed=-1', 'feed=abc', 'feed=999999999999']:
        with pytest.raises(argparse.ArgumentTypeError):
            source_rule(value)
    with pytest.raises(argparse.ArgumentTypeError):
        source_rule('feed=101', 100)


def test_quality_checks_handle_time_boundaries_and_volume_baselines():
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    def check(newest, counts=None, previous=None, volume=None):
        return publication_failures(counts or {'feed': 1}, newest, previous or {}, required=[],
                                    stale={'feed': 24}, volume_drop=volume or {}, now=now)
    assert check({'feed': iso(now - timedelta(hours=24))}) == []
    for date in [None, 'bad', iso(now + timedelta(seconds=1)), iso(now - timedelta(hours=24, seconds=1))]:
        assert check({'feed': date})[0]['reason'] == 'stale'
    fresh = {'feed': iso(now)}
    assert check(fresh, {'feed': 1251}, {'feed': 2500}, {'feed': 50}) == []
    assert check(fresh, {'feed': 1250}, {'feed': 2500}, {'feed': 50})[0]['reason'] == 'volume_drop'
    assert check(fresh, volume={'feed': 50}) == []
    assert check(fresh, volume={'typo': 50})[0]['reason'] == 'missing_source'
