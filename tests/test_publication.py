"""Synthetic patterns only: never commit a real leaked credential as a fixture."""
from dataclasses import asdict, replace

import pytest

from swiftioc.models import Indicator
from swiftioc.publication import filter_public_rows


def _candidate_key():
    return 'AI' + 'za' + '0123456789_' * 3 + 'ab'


def _row():
    return Indicator('hxxps://example[.]invalid/login', 'url', 'test',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                     'high', 'CLEAR', 'phishing', '', '')


@pytest.mark.parametrize('field', ['indicator', 'context', 'reference', 'tags', 'source'])
def test_omits_credentials_in_identity_or_metadata_without_mutation(field):
    safe = _row()
    unsafe = replace(safe, **{field: 'prefix?apiKey=' + _candidate_key()})
    baseline = asdict(unsafe)
    public, omitted = filter_public_rows([safe, unsafe])
    assert public == [safe]
    assert omitted == 1
    assert asdict(unsafe) == baseline


def test_nested_evidence_and_url_escapes_are_checked():
    key = _candidate_key()
    escaped = ''.join('%' + format(ord(c), '02X') for c in key)
    rows = [replace(_row(), vulnerability={'nvd': {'references': [{'url': key}]}}),
            replace(_row(), indicator='hxxps://example[.]invalid/?key=' + escaped)]
    assert filter_public_rows(rows) == ([], 2)


def test_ordinary_urls_and_short_pattern_fragments_remain_exact():
    rows = [_row(), replace(_row(), indicator='hxxps://example[.]invalid/AIza-short?case=Payload')]
    public, omitted = filter_public_rows(rows)
    assert public == rows
    assert omitted == 0
