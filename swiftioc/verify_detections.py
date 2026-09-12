"""Offline file-integrity checks for generated detection packs.

Usage: python -m swiftioc.verify_detections PACK_DIRECTORY [--json]
Checks consistency with a supplied manifest, not publisher authenticity or
whether the detections are suitable for the analyst's environment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict


REQUIRED_FILES = {'README.md', 'suricata/swiftioc.rules', 'suricata/sid-registry.json', 'dns/swiftioc.rpz'}
OPTIONAL_FILES = {'sigma/network-iocs.yml', 'sigma/dns-iocs.yml'}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Manifest contains duplicate JSON keys')
        result[key] = value
    return result


def _plain_file(root: Path, relative: str) -> Path:
    path = root
    if path.is_symlink():
        raise ValueError('Pack directory must not be a symbolic link')
    for part in Path(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f'Symbolic link is not allowed: {relative}')
    if not path.is_file():
        raise ValueError(f'Missing or non-regular file: {relative}')
    return path


def verify_detection_pack(root: Path) -> Dict[str, Any]:
    errors = []
    checked = 0
    try:
        manifest_path = _plain_file(root, 'manifest.json')
        with manifest_path.open('rb') as handle:
            content = handle.read(65537)
        if len(content) > 65536:
            raise ValueError('Manifest exceeds 64 KiB')
        manifest = json.loads(content, object_pairs_hook=_unique_pairs)
        if not isinstance(manifest, dict) or manifest.get('schema_version') != 2:
            raise ValueError('Expected a schema-version 2 manifest; regenerate older packs')
        files = manifest.get('files')
        if not isinstance(files, dict) or not REQUIRED_FILES <= files.keys():
            raise ValueError('Manifest is missing required file entries')
        if not files.keys() <= REQUIRED_FILES | OPTIONAL_FILES:
            raise ValueError('Manifest contains an unsupported file path')
        for relative, expected in sorted(files.items()):
            if (not isinstance(expected, dict) or type(expected.get('bytes')) is not int
                    or expected['bytes'] < 0 or not isinstance(expected.get('sha256'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', expected['sha256'])):
                errors.append(f'Invalid checksum entry: {relative}')
                continue
            try:
                path = _plain_file(root, relative)
                if path.stat().st_size != expected['bytes']:
                    errors.append(f'Byte-size mismatch: {relative}')
                    continue
                digest = hashlib.sha256()
                size = 0
                with path.open('rb') as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                        digest.update(chunk)
                        size += len(chunk)
                checked += 1
                if size != expected['bytes'] or digest.hexdigest() != expected['sha256']:
                    errors.append(f'Checksum or byte-size mismatch: {relative}')
            except (OSError, ValueError) as error:
                errors.append(str(error))
        for relative in sorted(OPTIONAL_FILES - files.keys()):
            path = root / relative
            if path.exists() or path.is_symlink():
                errors.append(f'Stale managed file absent from manifest: {relative}')
    except (OSError, ValueError, RecursionError) as error:
        errors.append(str(error))
    return {'valid': not errors, 'checked_files': checked, 'errors': errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pack', type=Path)
    parser.add_argument('--json', action='store_true', help='Print machine-readable verification results')
    args = parser.parse_args()
    result = verify_detection_pack(args.pack)
    if args.json:
        print(json.dumps(result))
    elif result['valid']:
        print(f"Verified {result['checked_files']} managed files against the manifest.")
    else:
        print('Detection pack verification failed:')
        for error in result['errors']:
            print(f'- {error}')
    return 0 if result['valid'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
