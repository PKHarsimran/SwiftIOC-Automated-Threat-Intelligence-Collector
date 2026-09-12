from __future__ import annotations

import hashlib
import json
import re
import uuid

import yaml

import swiftioc as si


def _indicator(value: str, kind: str, score: int = 90) -> si.Indicator:
    return si.Indicator(
        indicator=value,
        type=kind,
        source="feed-a,feed-b",
        first_seen="2026-09-08T00:00:00Z",
        last_seen="2026-09-08T01:00:00Z",
        confidence="high",
        tlp="CLEAR",
        tags="c2",
        reference="https://example.invalid/report",
        context="test fixture",
        score=score,
    )


def test_detection_pack_writes_valid_type_aware_artifacts(tmp_path):
    rows = [
        _indicator("1[.]2[.]3[.]4", "ipv4"),
        _indicator("2001:db8::1", "ipv6"),
        _indicator("evil[.]example", "domain"),
        _indicator("hxxps://evil[.]example/dropper", "url"),
        _indicator("a" * 64, "sha256"),
    ]

    manifest = si.write_detection_pack(
        tmp_path, rows, generated_at="2026-09-08T02:00:00Z"
    )

    assert manifest["policy"] == "review-required"
    assert manifest["included"] == {"domain": 1, "ipv4": 1, "ipv6": 1}
    assert manifest["skipped"] == {"sha256": 1, "url": 1}
    assert manifest["artifacts"] == {
        "sigma_rules": 2,
        "suricata_rules": 5,
        "rpz_domains": 1,
    }

    network = yaml.safe_load((tmp_path / "sigma" / "network-iocs.yml").read_text())
    assert network["logsource"] == {"category": "network_connection"}
    assert network["detection"]["ip_source"]["SourceIp"] == ["1.2.3.4", "2001:db8::1"]
    assert network["id"] == str(uuid.uuid5(si.DETECTION_NAMESPACE, "network-iocs"))

    dns = yaml.safe_load((tmp_path / "sigma" / "dns-iocs.yml").read_text())
    assert dns["detection"]["domain_exact"]["query"] == ["evil.example"]
    assert dns["detection"]["domain_subdomain"]["query|endswith"] == [".evil.example"]

    rules = (tmp_path / "suricata" / "swiftioc.rules").read_text()
    assert "1.2.3.4" in rules
    assert "[2001:db8::1]" in rules
    assert 'dotprefix; content:".evil.example"' in rules
    assert "hxxps" not in rules
    assert len(re.findall(r"\bsid:\d+;", rules)) == 5

    rpz = (tmp_path / "dns" / "swiftioc.rpz").read_text()
    assert "evil.example CNAME ." in rpz
    assert "*.evil.example CNAME ." in rpz
    assert json.loads((tmp_path / "manifest.json").read_text()) == manifest
    from swiftioc.verify_detections import verify_detection_pack
    assert verify_detection_pack(tmp_path) == {'valid': True, 'checked_files': 6, 'errors': []}


def test_detection_pack_is_deterministic_and_deduplicates(tmp_path):
    row = _indicator("Example[.]COM.", "domain")
    duplicate = _indicator("example.com", "domain")

    first = tmp_path / "first"
    second = tmp_path / "second"
    si.write_detection_pack(first, [row, duplicate], generated_at="2026-09-08T02:00:00Z")
    si.write_detection_pack(second, [duplicate, row], generated_at="2026-09-08T02:00:00Z")

    assert (first / "sigma" / "dns-iocs.yml").read_text() == (
        second / "sigma" / "dns-iocs.yml"
    ).read_text()
    assert (first / "suricata" / "swiftioc.rules").read_text() == (
        second / "suricata" / "swiftioc.rules"
    ).read_text()
    assert (first / "manifest.json").read_text() == (second / "manifest.json").read_text()


def test_detection_pack_records_invalid_observables(tmp_path):
    # Seed optional rules, then prove an empty deployable set cannot leave a
    # stale detection behind for the publisher to serve as current.
    si.write_detection_pack(
        tmp_path,
        [_indicator("1.2.3.4", "ipv4"), _indicator("evil.example", "domain")],
        generated_at="2026-09-08T01:00:00Z",
    )
    manifest = si.write_detection_pack(
        tmp_path,
        [_indicator("999.2.3.4", "ipv4"), _indicator("bad domain", "domain")],
        generated_at="2026-09-08T02:00:00Z",
    )
    assert manifest["included"] == {}
    assert manifest["skipped"] == {"invalid_domain": 1, "invalid_ipv4": 1}
    assert manifest["artifacts"] == {
        "sigma_rules": 0,
        "suricata_rules": 0,
        "rpz_domains": 0,
    }
    assert not (tmp_path / "sigma" / "network-iocs.yml").exists()
    assert not (tmp_path / "sigma" / "dns-iocs.yml").exists()


def test_suricata_collision_registry_keeps_unchanged_rule_sid(tmp_path):
    colliding_ip = _indicator("154.91.59.103", "ipv4")
    colliding_domain = _indicator("fakelouisvuitton.org", "domain")
    si.write_detection_pack(
        tmp_path, [colliding_ip, colliding_domain], generated_at="2026-09-08T02:00:00Z"
    )
    domain_key = "dns:fakelouisvuitton.org"
    base_sid = 4_000_000 + int(hashlib.sha256(domain_key.encode()).hexdigest()[:8], 16) % 900_000
    registry = json.loads((tmp_path / "suricata" / "sid-registry.json").read_text())
    domain_sid = registry[domain_key]
    assert domain_sid != base_sid

    si.write_detection_pack(
        tmp_path, [colliding_domain], generated_at="2026-09-08T03:00:00Z"
    )

    registry = json.loads((tmp_path / "suricata" / "sid-registry.json").read_text())
    assert registry[domain_key] == domain_sid
    assert f"sid:{domain_sid};" in (tmp_path / "suricata" / "swiftioc.rules").read_text()


def test_rpz_serial_advances_when_two_revisions_share_a_timestamp(tmp_path):
    first = si.write_detection_pack(
        tmp_path, [_indicator("first.example", "domain")], generated_at="2026-09-08T02:00:00Z"
    )
    second = si.write_detection_pack(
        tmp_path, [_indicator("second.example", "domain")], generated_at="2026-09-08T02:00:00Z"
    )

    assert second["rpz_serial"] == first["rpz_serial"] + 1
    assert f"({second['rpz_serial']} " in (tmp_path / "dns" / "swiftioc.rpz").read_text()


def test_rpz_triggers_remain_relative_to_the_policy_zone(tmp_path):
    si.write_detection_pack(
        tmp_path, [_indicator("Evil[.]Example.", "domain")],
        generated_at="2026-09-08T02:00:00Z",
    )
    zone = (tmp_path / "dns" / "swiftioc.rpz").read_text()
    triggers = [line.split() for line in zone.splitlines() if " CNAME " in line]
    assert len(triggers) == 2
    for owner, record_type, target in triggers:
        assert not owner.endswith("."), "Absolute triggers escape the RPZ origin"
        assert record_type == "CNAME"
        assert target == ".", "NXDOMAIN action must remain an absolute root target"
    assert {owner for owner, *_ in triggers} == {"evil.example", "*.evil.example"}


def test_new_collision_cannot_steal_existing_or_inactive_sid(tmp_path):
    # These two real hash collisions also cover insertion order: IP rules are
    # generated before DNS rules, even when the DNS assignment already exists.
    domain = _indicator('fakelouisvuitton.org', 'domain')
    address = _indicator('154.91.59.103', 'ipv4')
    stamp = '2026-09-08T02:00:00Z'
    si.write_detection_pack(tmp_path, [domain], generated_at=stamp)
    registry_path = tmp_path / 'suricata/sid-registry.json'
    original = json.loads(registry_path.read_text())['dns:fakelouisvuitton.org']
    si.write_detection_pack(tmp_path, [address], generated_at=stamp)
    registry = json.loads(registry_path.read_text())
    assert registry['dns:fakelouisvuitton.org'] == original
    assert len(set(registry.values())) == len(registry)
    si.write_detection_pack(tmp_path, [address, domain], generated_at=stamp)
    registry = json.loads(registry_path.read_text())
    assert registry['dns:fakelouisvuitton.org'] == original
    assert len(set(registry.values())) == len(registry)


def test_corrupt_detection_state_recovers_without_boolean_or_duplicate_sids(tmp_path):
    from swiftioc.detections import _load_detection_state
    (tmp_path / 'suricata').mkdir()
    (tmp_path / 'dns').mkdir()
    (tmp_path / 'suricata/sid-registry.json').write_text(json.dumps({'a': True, 'b': 4000001, 'c': 4000001}))
    (tmp_path / 'dns/swiftioc.rpz').write_bytes(b'\xff\xfe')
    registry, serial = _load_detection_state(tmp_path)
    assert registry == {'b': 4000001}
    assert serial is None
