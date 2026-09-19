from __future__ import annotations

import json
import subprocess
import sys

import pytest

from swiftioc.detections import write_detection_pack
from swiftioc.verify_detections import verify_detection_pack


def _pack(path):
    return write_detection_pack(path, [], generated_at='2026-09-12T00:00:00Z')


def test_verification_detects_same_size_corruption_missing_and_stale_rules(tmp_path):
    manifest = _pack(tmp_path)
    assert manifest['schema_version'] == 2
    assert verify_detection_pack(tmp_path) == {'valid': True, 'checked_files': 4, 'errors': []}
    rule = tmp_path / 'suricata/swiftioc.rules'
    content = rule.read_bytes()
    rule.write_bytes(b'!' + content[1:])
    assert not verify_detection_pack(tmp_path)['valid']
    rule.write_bytes(content)
    rule.unlink()
    assert not verify_detection_pack(tmp_path)['valid']
    rule.write_bytes(content)
    (tmp_path / 'sigma').mkdir()
    (tmp_path / 'sigma/dns-iocs.yml').write_text('old detection')
    assert 'Stale managed file' in verify_detection_pack(tmp_path)['errors'][0]


@pytest.mark.parametrize('kind', ['traversal', 'absolute', 'missing', 'bad_hash', 'bad_size', 'old_schema', 'invalid_json'])
def test_verification_rejects_incompatible_or_unsafe_manifests(tmp_path, kind):
    manifest = _pack(tmp_path)
    if kind in {'traversal', 'absolute'}:
        manifest['files']['../outside' if kind == 'traversal' else '/outside'] = manifest['files']['README.md']
    elif kind == 'missing':
        del manifest['files']['README.md']
    elif kind == 'bad_hash':
        manifest['files']['README.md']['sha256'] = 'broken'
    elif kind == 'bad_size':
        manifest['files']['README.md']['bytes'] = True
    elif kind == 'old_schema':
        manifest['schema_version'] = 1
    (tmp_path / 'manifest.json').write_text('{' if kind == 'invalid_json' else json.dumps(manifest))
    assert not verify_detection_pack(tmp_path)['valid']


def test_verifier_refuses_symlinks_in_file_and_parent(tmp_path):
    root = tmp_path / 'pack'
    _pack(root)
    rule = root / 'suricata/swiftioc.rules'
    outside = tmp_path / 'outside'
    rule.rename(outside)
    try:
        rule.symlink_to(outside)
    except OSError:
        pytest.skip('Symlink creation is unavailable')
    assert not verify_detection_pack(root)['valid']
    rule.unlink()
    outside.rename(rule)
    (root / 'suricata').rename(tmp_path / 'rules')
    (root / 'suricata').symlink_to(tmp_path / 'rules', target_is_directory=True)
    assert not verify_detection_pack(root)['valid']


def test_verifier_cli_provides_json_and_failure_exit_code(tmp_path):
    _pack(tmp_path)
    command = [sys.executable, '-m', 'swiftioc.verify_detections', str(tmp_path), '--json']
    good = subprocess.run(command, capture_output=True, text=True)
    assert good.returncode == 0
    assert json.loads(good.stdout)['valid'] is True
    (tmp_path / 'README.md').write_text('modified')
    bad = subprocess.run(command, capture_output=True, text=True)
    assert bad.returncode == 1
    assert json.loads(bad.stdout)['valid'] is False


@pytest.mark.parametrize('payload', [b' ' * 65537, b'\xff', b'{"schema_version":2,"schema_version":1}', b'[' * 2000 + b']' * 2000])
def test_verifier_reports_malformed_manifests_without_crashing(tmp_path, payload):
    (tmp_path / 'manifest.json').write_bytes(payload)
    result = verify_detection_pack(tmp_path)
    assert result['valid'] is False
    assert result['checked_files'] == 0
    assert result['errors']
