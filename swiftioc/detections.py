"""Compile curated SwiftIOC intelligence into reviewable detection artifacts."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import yaml

from .models import Indicator, classify, parse_dt, refang
from .writers import STIX_NAMESPACE, _atomic_text_writer


DETECTION_NAMESPACE = uuid.uuid5(STIX_NAMESPACE, "detection-pack")
DEPLOYABLE_TYPES = {"ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr", "domain"}


def _unique_observables(rows: Iterable[Indicator]) -> Tuple[Dict[str, List[str]], Counter[str]]:
    """Return validated, raw observables grouped by type and skipped counts."""
    grouped: Dict[str, set[str]] = {name: set() for name in sorted(DEPLOYABLE_TYPES)}
    skipped: Counter[str] = Counter()
    for row in rows:
        kind = str(row.type).lower()
        value = refang(row.indicator).strip()
        if kind not in DEPLOYABLE_TYPES:
            skipped[kind or "unknown"] += 1
            continue
        try:
            if kind in {"ipv4", "ipv6"}:
                parsed = ipaddress.ip_address(value)
                expected = 4 if kind == "ipv4" else 6
                if parsed.version != expected:
                    raise ValueError("address family mismatch")
                value = str(parsed)
            elif kind in {"ipv4_cidr", "ipv6_cidr"}:
                parsed_network = ipaddress.ip_network(value, strict=False)
                expected = 4 if kind == "ipv4_cidr" else 6
                if parsed_network.version != expected:
                    raise ValueError("network family mismatch")
                value = str(parsed_network)
            else:
                value = value.lower().rstrip(".")
                if classify(value) != "domain":
                    raise ValueError("invalid domain")
        except ValueError:
            skipped[f"invalid_{kind}"] += 1
            continue
        grouped[kind].add(value)
    return {kind: sorted(values) for kind, values in grouped.items()}, skipped


def _sigma_rule(*, name: str, title: str, description: str, logsource: Dict[str, str],
                detection: Dict[str, Any], generated_at: str) -> str:
    observed = parse_dt(generated_at)
    document: Dict[str, Any] = {
        "title": title,
        "id": str(uuid.uuid5(DETECTION_NAMESPACE, name)),
        "status": "experimental",
        "description": description,
        "references": ["https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/"],
        "author": "SwiftIOC",
        "date": observed.strftime("%Y-%m-%d") if observed else generated_at[:10],
        "tags": ["attack.command_and_control"],
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Legitimate infrastructure sharing an address or domain; validate with local context."],
        "level": "high",
    }
    return yaml.safe_dump(document, sort_keys=False, allow_unicode=True, width=120)


def _sigma_documents(grouped: Dict[str, List[str]], generated_at: str) -> Dict[str, str]:
    addresses = grouped["ipv4"] + grouped["ipv6"]
    networks = grouped["ipv4_cidr"] + grouped["ipv6_cidr"]
    documents: Dict[str, str] = {}
    if addresses or networks:
        detection: Dict[str, Any] = {}
        if addresses:
            detection.update({
                "ip_source": {"SourceIp": addresses},
                "ip_destination": {"DestinationIp": addresses},
            })
        if networks:
            detection.update({
                "ip_source_network": {"SourceIp|cidr": networks},
                "ip_destination_network": {"DestinationIp|cidr": networks},
            })
        detection["condition"] = "1 of ip_*"
        documents["sigma/network-iocs.yml"] = _sigma_rule(
            name="network-iocs",
            title="SwiftIOC high-confidence network indicators",
            description="Detects network traffic where either endpoint matches SwiftIOC's curated high-confidence feed.",
            logsource={"category": "network_connection"},
            detection=detection,
            generated_at=generated_at,
        )
    if grouped["domain"]:
        documents["sigma/dns-iocs.yml"] = _sigma_rule(
            name="dns-iocs",
            title="SwiftIOC high-confidence DNS indicators",
            description="Detects DNS queries ending in a domain from SwiftIOC's curated high-confidence feed.",
            logsource={"category": "dns"},
            detection={
                "domain_exact": {"query": grouped["domain"]},
                "domain_subdomain": {"query|endswith": [f".{value}" for value in grouped["domain"]]},
                "condition": "domain_exact or domain_subdomain",
            },
            generated_at=generated_at,
        )
    return documents


def _sid(value: str, used: set[int], registry: Dict[str, int]) -> int:
    registered = registry.get(value)
    if registered is not None and registered not in used:
        used.add(registered)
        return registered
    candidate = 4_000_000 + int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:8], 16) % 900_000
    while candidate in used:
        candidate = 4_000_000 + ((candidate - 4_000_000 + 1) % 900_000)
    used.add(candidate)
    registry[value] = candidate
    return candidate


def _suricata_rules(grouped: Dict[str, List[str]], registry: Dict[str, int]) -> Tuple[str, int]:
    rules: List[str] = []
    used: set[int] = set()
    addresses = grouped["ipv4"] + grouped["ipv6"] + grouped["ipv4_cidr"] + grouped["ipv6_cidr"]
    for address in addresses:
        target = f"[{address}]" if ":" in address else address
        for direction, header in (
            ("inbound", f"alert ip {target} any -> $HOME_NET any"),
            ("outbound", f"alert ip $HOME_NET any -> {target} any"),
        ):
            sid = _sid(f"ip:{address}:{direction}", used, registry)
            rules.append(
                f'{header} (msg:"SwiftIOC {direction} high-confidence IP match"; '
                f'classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
    for domain in grouped["domain"]:
        sid = _sid(f"dns:{domain}", used, registry)
        rules.append(
            'alert dns $HOME_NET any -> any 53 '
            f'(msg:"SwiftIOC high-confidence DNS match"; dns.query; dotprefix; content:".{domain}"; '
            f'nocase; endswith; classtype:trojan-activity; sid:{sid}; rev:1;)'
        )
    header = (
        "# SwiftIOC high-confidence detection pack\n"
        "# Review and tune against local allowlists before enabling enforcement.\n"
    )
    return header + "\n".join(rules) + ("\n" if rules else ""), len(rules)


def _load_detection_state(out_dir: Path) -> Tuple[Dict[str, int], int | None]:
    registry: Dict[str, int] = {}
    try:
        previous = json.loads(
            (out_dir / "suricata" / "sid-registry.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, TypeError):
        previous = {}
    if isinstance(previous, dict):
        for key, value in previous.items():
            if isinstance(key, str) and isinstance(value, int) and 1 <= value <= 0xFFFFFFFF:
                registry[key] = value

    previous_serial: int | None = None
    try:
        zone = (out_dir / "dns" / "swiftioc.rpz").read_text(encoding="utf-8")
        match = re.search(r"root\.localhost\.\s*\((\d+)", zone)
        if match:
            value = int(match.group(1))
            if 0 <= value <= 0xFFFFFFFF:
                previous_serial = value
    except OSError:
        pass
    return registry, previous_serial


def _rpz_serial(generated_at: str, previous: int | None) -> int:
    observed = parse_dt(generated_at)
    candidate = int(observed.timestamp()) if observed else 1
    candidate = max(1, min(candidate, 0xFFFFFFFF))
    if previous is None or candidate > previous:
        return candidate
    return 0 if previous == 0xFFFFFFFF else previous + 1


def _rpz_zone(domains: Sequence[str], serial: int) -> str:
    lines = [
        "$TTL 300",
        f"@ IN SOA localhost. root.localhost. ({serial} 300 60 86400 60)",
        "@ IN NS localhost.",
    ]
    for domain in domains:
        lines.extend((f"{domain}. CNAME .", f"*.{domain}. CNAME ."))
    return "\n".join(lines) + "\n"


def _pack_readme() -> str:
    return """# SwiftIOC Detection Pack

Generated from the curated high-confidence feed. Treat these artifacts as detection-as-code inputs: review them, apply local allowlists, test in alert-only mode, and then promote them through your normal change process.

- `sigma/network-iocs.yml` matches source or destination IPs in normalized network-connection events.
- `sigma/dns-iocs.yml` matches malicious domain suffixes in normalized DNS events.
- `suricata/swiftioc.rules` contains stable-SID inbound, outbound, and DNS alert rules.
- `suricata/sid-registry.json` preserves collision-resolved SIDs across feed revisions.
- `dns/swiftioc.rpz` is a response-policy zone for exact domains and their subdomains.
- `manifest.json` records coverage and every unsupported or invalid indicator type that was skipped.

Compile Sigma for your backend with Sigma CLI, load the Suricata file through your managed rules directory, or configure the RPZ as a secondary policy zone. Field mappings and network variables vary by environment, so validate generated detections before production use.
"""


def write_detection_pack(out_dir: Path, rows: Sequence[Indicator], *, generated_at: str) -> Dict[str, Any]:
    """Write Sigma, Suricata, and DNS RPZ artifacts plus an auditable manifest."""
    grouped, skipped = _unique_observables(rows)
    sid_registry, previous_rpz_serial = _load_detection_state(out_dir)
    sigma = _sigma_documents(grouped, generated_at)
    suricata, suricata_count = _suricata_rules(grouped, sid_registry)
    rpz_serial = _rpz_serial(generated_at, previous_rpz_serial)
    artifacts: Dict[str, str] = {
        **sigma,
        "suricata/swiftioc.rules": suricata,
        "suricata/sid-registry.json": json.dumps(
            dict(sorted(sid_registry.items())), ensure_ascii=False, indent=2
        ) + "\n",
        "dns/swiftioc.rpz": _rpz_zone(grouped["domain"], rpz_serial),
        "README.md": _pack_readme(),
    }
    # Optional Sigma families can disappear as the curated feed changes. Never
    # leave an older rule on disk where a publisher would mistake it for part
    # of the current pack.
    managed_optional = {"sigma/network-iocs.yml", "sigma/dns-iocs.yml"}
    for relative in managed_optional - artifacts.keys():
        (out_dir / relative).unlink(missing_ok=True)
    included = {kind: len(values) for kind, values in grouped.items() if values}
    manifest: Dict[str, Any] = {
        "schema_version": 1,
        "generated_at": generated_at,
        "source": "SwiftIOC high-confidence feed",
        "policy": "review-required",
        "rpz_serial": rpz_serial,
        "included": included,
        "skipped": dict(sorted(skipped.items())),
        "artifacts": {
            "sigma_rules": len(sigma),
            "suricata_rules": suricata_count,
            "rpz_domains": len(grouped["domain"]),
        },
    }
    for relative, content in artifacts.items():
        with _atomic_text_writer(out_dir / relative) as handle:
            handle.write(content)
    with _atomic_text_writer(out_dir / "manifest.json") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return manifest
