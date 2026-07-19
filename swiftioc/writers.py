"""Output writers: CSV/TSV/JSON/JSONL, STIX 2.1, MISP feed, RSS, badge, history."""
from __future__ import annotations

import csv
import json
import re
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .http_client import logger
from .models import Indicator, iso, now_utc, parse_dt, refang
from .scoring import source_count

# Stable namespace for deterministic STIX 2.1 identifiers (uuid5).
STIX_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "swiftioc.threatintel")
# Producer identity and the canonical shareable TLP marking. We use the
# well-known TLP:WHITE object (id/created are fixed by the STIX spec): it is the
# pre-2.1 name for TLP:CLEAR and is accepted by every STIX 2.0/2.1 tool, whereas
# the newer TLP:CLEAR object is rejected by many current validators.
STIX_IDENTITY_ID = f"identity--{uuid.uuid5(STIX_NAMESPACE, 'identity:swiftioc')}"
STIX_TLP_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
# STIX hashing-algorithm-ov names keyed by our internal hash type.
STIX_HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}


# ---------------- writers ----------------
CSV_HEADER = ["indicator", "type", "source", "first_seen", "last_seen", "confidence", "score", "sightings", "tlp", "tags", "reference", "context"]


_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Neutralize CSV/formula injection (CWE-1236).

    tags/context/reference/indicator are attacker-influenced on
    public-submission sources (ThreatFox, MalwareBazaar) or free-text
    RSS/OSINT extraction. Excel/LibreOffice/Sheets treat a leading
    =/+/-/@ (or a raw tab/CR, which can smuggle one past a naive check) as a
    formula/DDE trigger when the CSV/TSV is opened — these files are direct
    analyst downloads (public/index.html), not an internal artifact.
    Prefixing with an apostrophe is the standard OWASP mitigation.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_TRIGGERS):
        return "'" + value
    return value


def _csv_row(r: Indicator) -> List[Any]:
    return [_csv_safe(v) for v in (r.indicator, r.type, r.source, r.first_seen, r.last_seen, r.confidence, r.score, r.sightings, r.tlp, r.tags, r.reference, r.context)]


def write_csv(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADER)
        for r in rows:
            w.writerow(_csv_row(r))


def write_tsv(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(CSV_HEADER)
        for r in rows:
            w.writerow(_csv_row(r))


def write_json(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, ensure_ascii=False, indent=2)


def write_jsonl(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")


def write_dashboard_feed(path: Path, rows: List[Indicator], *, limit: int = 1000) -> int:
    """Write the compact feed the web dashboard downloads.

    The full latest.jsonl can run to many megabytes, which every dashboard
    visitor would otherwise download (and which overflows localStorage, so it
    can't even be cached client-side). This trims to the top ``limit`` rows by
    (score, corroboration, recency) and drops fields the dashboard never
    renders, cutting the payload by ~98%. Global stats come from run.json.
    """
    ranked = sorted(
        rows, key=lambda r: (r.score, source_count(r), r.last_seen, r.indicator), reverse=True
    )[:limit]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in ranked:
            f.write(
                json.dumps(
                    {
                        "indicator": r.indicator,
                        "type": r.type,
                        "source": r.source,
                        "first_seen": r.first_seen,
                        "last_seen": r.last_seen,
                        "confidence": r.confidence,
                        "score": r.score,
                        "sightings": r.sightings,
                        "tags": r.tags,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(ranked)


def _stix_pattern(itype: str, indicator: str) -> Optional[str]:
    """Build a STIX 2.1 comparison expression for an indicator, or None.

    Values are refanged and single quotes escaped so the pattern stays valid.
    Types without a core STIX 2.1 observable (ja3/ja3s/btc_address — none of
    these are in the SCO registry) are emitted under an ``x-swiftioc-*``
    custom object so they are preserved rather than dropped or mapped onto a
    non-existent core type.
    """
    value = refang(indicator).replace("\\", "\\\\").replace("'", "\\'")
    if itype in {"ipv4", "ipv4_cidr"}:
        return f"[ipv4-addr:value = '{value}']"
    if itype in {"ipv6", "ipv6_cidr"}:
        return f"[ipv6-addr:value = '{value}']"
    if itype == "domain":
        return f"[domain-name:value = '{value}']"
    if itype == "url":
        return f"[url:value = '{value}']"
    if itype in STIX_HASH_NAMES:
        return f"[file:hashes.'{STIX_HASH_NAMES[itype]}' = '{value}']"
    if itype == "email":
        return f"[email-addr:value = '{value}']"
    if itype in {"ja3", "ja3s", "btc_address"}:
        return f"[x-swiftioc-{itype.replace('_', '-')}:value = '{value}']"
    return None


def write_stix(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = iso(now_utc())
    common = {
        "created": now,
        "modified": now,
        "created_by_ref": STIX_IDENTITY_ID,
        "object_marking_refs": [STIX_TLP_ID],
    }
    # Producer identity + TLP:CLEAR marking so consumers have provenance.
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity", "spec_version": "2.1", "id": STIX_IDENTITY_ID,
            "created": now, "modified": now, "name": "SwiftIOC", "identity_class": "system",
        },
        {
            # Canonical TLP:WHITE marking (fixed id/created per the STIX spec).
            "type": "marking-definition", "spec_version": "2.1", "id": STIX_TLP_ID,
            "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
            "name": "TLP:WHITE", "definition": {"tlp": "white"},
        },
    ]
    for r in rows:
        # CVEs are SDOs, not observable patterns: emit a proper vulnerability.
        if r.type == "cve":
            vid = uuid.uuid5(STIX_NAMESPACE, f"vulnerability:{r.indicator}")
            objects.append({
                "type": "vulnerability", "spec_version": "2.1",
                "id": f"vulnerability--{vid}", **common,
                "name": r.indicator,
                "external_references": [{"source_name": "cve", "external_id": r.indicator}],
                "labels": [t for t in r.tags.split(",") if t],
                "x_swiftioc_source": r.source, "x_swiftioc_reference": r.reference,
            })
            continue
        pattern = _stix_pattern(r.type, r.indicator)
        if not pattern:
            logger.debug("STIX: no pattern for type %s (%s)", r.type, r.indicator)
            continue
        # Deterministic RFC 4122 UUID so re-imports stay idempotent downstream.
        sid = uuid.uuid5(STIX_NAMESPACE, f"{r.type}:{r.indicator}")
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{sid}", **common,
            "name": f"{r.type}:{r.indicator}", "pattern": pattern, "pattern_type": "stix",
            "valid_from": r.first_seen,
            # Computed 0-100 score (corroboration + decay) when available;
            # fall back to the coarse confidence mapping for unscored rows.
            "confidence": r.score if r.score > 0 else (70 if r.confidence == "high" else 50 if r.confidence == "medium" else 30),
            "labels": [t for t in r.tags.split(",") if t],
            "x_swiftioc_source": r.source, "x_swiftioc_tlp": r.tlp, "x_swiftioc_reference": r.reference,
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(STIX_NAMESPACE, 'bundle:' + now)}", "objects": objects}
    with path.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)


# ---------------- MISP feed ----------------
# MISP attribute type per our indicator type. See
# https://www.misp-project.org/datamodels/#attribute-types. CIDRs use the
# same ip-src/ip-dst types (MISP accepts CIDR notation in the value).
MISP_ATTRIBUTE_TYPES = {
    "ipv4": "ip-dst",
    "ipv4_cidr": "ip-dst",
    "ipv6": "ip-dst",
    "ipv6_cidr": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "email": "email-src",
    "cve": "vulnerability",
    "btc_address": "btc",
    "ja3": "ja3-fingerprint-md5",
    "ja3s": "ja3-fingerprint-md5",
}

# MISP validates category/type combinations on feed import, so each type
# needs its own valid category rather than a generic fallback — a TLS
# fingerprint tagged "Payload delivery" (a hash/file category) can be
# rejected or silently dropped. Per the MISP attribute vocabulary
# (https://www.misp-project.org/datamodels/#attribute-types):
MISP_CATEGORY_BY_TYPE = {
    "ipv4": "Network activity",
    "ipv4_cidr": "Network activity",
    "ipv6": "Network activity",
    "ipv6_cidr": "Network activity",
    "domain": "Network activity",
    "url": "Network activity",
    "md5": "Payload delivery",
    "sha1": "Payload delivery",
    "sha256": "Payload delivery",
    "sha512": "Payload delivery",
    "email": "Network activity",
    "cve": "External analysis",
    "btc_address": "Financial fraud",
    "ja3": "Network activity",
    "ja3s": "Network activity",
}


def write_misp_feed(out_dir: Path, rows: List[Indicator], *, run_ts: str) -> int:
    """Write a MISP-compatible feed: manifest.json + one event JSON.

    This is the "MISP feed" format (Sync > Feeds > add a feed with this URL),
    not the full MISP API — no server or API key needed on either side. A
    single, stable event (fixed UUID, overwritten every run) represents the
    feed's *current* state — matching the "top IOCs only" retention model.
    A per-run UUID would create a new event file on every collection and
    never clean up, growing the repo unboundedly.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    event_uuid = str(uuid.uuid5(STIX_NAMESPACE, "misp-event:swiftioc-current"))
    attributes = []
    for r in rows:
        misp_type = MISP_ATTRIBUTE_TYPES.get(r.type)
        if not misp_type:
            continue
        value = refang(r.indicator) if r.type in {"ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr", "domain", "url"} else r.indicator
        attributes.append(
            {
                "uuid": str(uuid.uuid5(STIX_NAMESPACE, f"misp-attr:{r.type}:{r.indicator}")),
                "type": misp_type,
                "category": MISP_CATEGORY_BY_TYPE.get(r.type, "Payload delivery"),
                "value": value,
                "to_ids": misp_type != "vulnerability",
                "timestamp": str(int((parse_dt(r.last_seen) or now_utc()).timestamp())),
                "comment": f"score={r.score} source={r.source}",
                "Tag": [{"name": t} for t in r.tags.split(",") if t][:10],
            }
        )
    event = {
        "Event": {
            "uuid": event_uuid,
            "info": f"SwiftIOC feed — {run_ts}",
            "date": run_ts[:10],
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "3",
            "publish_timestamp": str(int(now_utc().timestamp())),
            "Orgc": {"name": "SwiftIOC"},
            "Attribute": attributes,
        }
    }
    (out_dir / f"{event_uuid}.json").write_text(
        json.dumps(event, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    manifest = {
        event_uuid: {
            "Orgc": {"name": "SwiftIOC"},
            "Tag": [],
            "info": event["Event"]["info"],
            "date": event["Event"]["date"],
            "analysis": "2",
            "threat_level_id": "2",
            "publish_timestamp": event["Event"]["publish_timestamp"],
        }
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return len(attributes)


# ---------------- RSS / badge / trend outputs ----------------
_XML_ILLEGAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _xml_escape(text: str) -> str:
    # XML 1.0 forbids most C0 control characters outside tab/CR/LF; a raw one
    # in attacker-influenced context/tags (e.g. universal-parser free text)
    # would otherwise produce a structurally invalid rss.xml.
    text = _XML_ILLEGAL_CONTROL_RE.sub("", text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def write_rss_feed(path: Path, rows: List[Indicator], *, site_url: str, limit: int = 50) -> int:
    """Write an RSS 2.0 feed of the newest high-confidence indicators.

    Lets people subscribe to "what's new" instead of polling the dashboard,
    and gives feed aggregators (threatfeeds.io-style directories) something
    to index.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # first_seen, not last_seen: last_seen is refreshed to this run's
    # fetch-completion time for every re-observed indicator, so within one
    # run it barely varies and effectively defers to score — biasing
    # "newest" toward whatever scores highest rather than what was actually
    # newly discovered. first_seen is stable across runs and matches the
    # pubDate already used below and the dashboard's own "New" definition.
    ranked = sorted(rows, key=lambda r: (r.first_seen, r.score), reverse=True)[:limit]
    now_rfc822 = now_utc().strftime("%a, %d %b %Y %H:%M:%S +0000")
    items = []
    for r in ranked:
        pub = parse_dt(r.first_seen) or now_utc()
        title = _xml_escape(f"[{r.score}] {r.type}: {r.indicator}")
        sources = ", ".join(sorted(set(s for s in r.source.split(",") if s)))
        desc = _xml_escape(f"Score {r.score}, confidence {r.confidence}, sources: {sources}, tags: {r.tags}")
        guid = uuid.uuid5(STIX_NAMESPACE, f"rss:{r.type}:{r.indicator}")
        items.append(
            "    <item>\n"
            f"      <title>{title}</title>\n"
            f"      <description>{desc}</description>\n"
            f"      <guid isPermaLink=\"false\">{guid}</guid>\n"
            f"      <pubDate>{pub.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>\n"
            "    </item>"
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0"><channel>\n'
        "  <title>SwiftIOC — Newest High-Confidence IOCs</title>\n"
        f"  <link>{_xml_escape(site_url)}</link>\n"
        "  <description>Freshest scored, cross-source-corroborated indicators of compromise.</description>\n"
        f"  <lastBuildDate>{now_rfc822}</lastBuildDate>\n"
        + "\n".join(items)
        + "\n</channel></rss>\n"
    )
    path.write_text(xml, encoding="utf-8")
    return len(ranked)


def write_badge_json(path: Path, *, total: int, generated: str) -> None:
    """Write a shields.io endpoint-badge JSON: ![IOCs](.../badge.json)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schemaVersion": 1,
        "label": "IOCs",
        "message": f"{total:,} · updated {generated}",
        "color": "blue",
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def write_history(path: Path, entry: Dict[str, Any], *, max_entries: int = 90) -> List[Dict[str, Any]]:
    """Append one run's summary stats to a capped rolling history.

    Powers the dashboard trend sparkline. Tolerant of a missing/corrupt file
    (starts fresh) so it never blocks a run.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    history: List[Dict[str, Any]] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                history = [e for e in loaded if isinstance(e, dict)]
        except json.JSONDecodeError:
            history = []
    history.append(entry)
    history = history[-max_entries:]
    path.write_text(json.dumps(history, ensure_ascii=False), encoding="utf-8")
    return history


def write_changelog(path: Path, counts: Dict[str, int], total: int, *, max_entries: int = 50) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = iso(now_utc())
    entry_lines = [f"## {ts}", "", f"Total indicators: **{total}**", "", "### By source"]
    entry_lines.extend(f"- {k}: {v}" for k, v in sorted(counts.items()))
    entry = "\n".join(entry_lines).strip()

    # Read existing run entries and keep only the most recent ``max_entries`` so
    # the changelog can be committed every run without growing without bound.
    existing: List[str] = []
    if path.exists():
        text = path.read_text(encoding="utf-8")
        for chunk in re.split(r"(?m)^## ", text)[1:]:
            existing.append("## " + chunk.strip())

    entries = existing + [entry]  # chronological: newest last
    entries = entries[-max_entries:]
    body = "# Changelog\n\n" + "\n\n".join(entries) + "\n"
    path.write_text(body, encoding="utf-8")


