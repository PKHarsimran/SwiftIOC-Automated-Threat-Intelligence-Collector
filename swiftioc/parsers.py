"""Parser registry and all source adapters (fetch_* functions).

``http_get`` and ``load_feedparser`` are looked up through ``_pkg`` (a
self-import of the ``swiftioc`` package) *at call time* rather than imported
directly. This is deliberate, not an oversight: tests monkeypatch them as
``monkeypatch.setattr(swiftioc, "http_get", ...)`` on the top-level package.
A direct ``from .http_client import http_get`` would bind a local name at
import time that the monkeypatch — which only reassigns the *package's*
attribute — would never see, so parsers would keep hitting the real network
in tests. ``_pkg.http_get(...)`` re-resolves the attribute on every call, so
it always sees whatever ``swiftioc.http_get`` currently points to. The
self-import is safe here because ``_pkg`` is only dereferenced inside
function bodies, never at module-import time (see the circular-import note
in ``__init__.py``).
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta
from importlib import import_module
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import requests

import swiftioc as _pkg

from .extract import extract_indicators_from_text
from .http_client import choose_ua, ensure_text, logger
from .models import (
    DATE_FIELD_RE,
    JA3_RE,
    TAGS_FIELD_RE,
    Indicator,
    classify,
    defang_min,
    iso,
    now_utc,
    parse_dt,
)


# ---------------- parser registry ----------------
ParserFunc = Callable[..., List["Indicator"]]


class ParserRegistry(dict):
    def register(self, names: Iterable[str]) -> Callable[[ParserFunc], ParserFunc]:
        def decorator(func: ParserFunc) -> ParserFunc:
            for name in names:
                key = name.lower()
                if key in self:
                    raise ValueError(f"Parser already registered for '{name}'")
                self[key] = func
            return func

        return decorator


PARSERS: ParserRegistry = ParserRegistry()


def register_parser(*names: str) -> Callable[[ParserFunc], ParserFunc]:
    if not names:
        raise ValueError("At least one parser name is required")
    return PARSERS.register(names)


def resolve_parser(identifier: str) -> ParserFunc:
    key = identifier.lower()
    if key in PARSERS:
        return PARSERS[key]
    module_name: Optional[str] = None
    attr_name: Optional[str] = None
    if ":" in identifier:
        module_name, attr_name = identifier.split(":", 1)
    elif "." in identifier:
        module_name, attr_name = identifier.rsplit(".", 1)
    if not module_name or not attr_name:
        raise KeyError(f"Unknown parser '{identifier}'")
    module = import_module(module_name)
    func = getattr(module, attr_name)
    if not callable(func):
        raise TypeError(f"Parser '{identifier}' is not callable")
    return func  # type: ignore[return-value]



# --------------- adapters (no hard-coded refs) ---------------
@register_parser("kev", "cisa_kev")
def fetch_cisa_kev(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    data = json.loads(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for it in data.get("vulnerabilities", []) or []:
        cve = it.get("cveID")
        pub = parse_dt(it.get("dateAdded"))
        if not cve:
            continue
        out.append(
            Indicator(
                indicator=cve, type="cve", source=source,
                first_seen=iso(pub or now), last_seen=iso(now),
                confidence="high", tlp="CLEAR",
                tags="cve,exploited-in-the-wild",
                reference=ref_url or "",
                context=it.get("notes") or it.get("shortDescription") or "CISA KEV",
            )
        )
    return out


@register_parser("nvd", "nist_nvd", "nist_nvd_recent")
def fetch_nvd_recent(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    now = now_utc()
    # The NVD 2.0 API returns the *oldest* CVEs first (startIndex 0), so an
    # unfiltered query yields 1999-era CVEs that the lookback window then drops,
    # leaving zero. Constrain it to CVEs modified within the window (the API
    # requires both bounds and caps the range at 120 days; a lookback window is
    # always well inside that).
    from urllib.parse import parse_qs, urlencode, urlparse
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    # Match the NVD host by parsed hostname, not a substring of the whole URL,
    # so a lookalike like nvd.nist.gov.evil.com or ?x=nvd.nist.gov can't trip it.
    # Use endswith so the real config host (services.nvd.nist.gov) still matches.
    if host == "nvd.nist.gov" or host.endswith(".nvd.nist.gov"):
        query = parse_qs(parsed.query)
        if not any(k in query for k in ("lastModStartDate", "pubStartDate")):
            fmt = "%Y-%m-%dT%H:%M:%S.000"
            start = max(ws, now - timedelta(days=119))
            query["lastModStartDate"] = [start.strftime(fmt)]
            query["lastModEndDate"] = [now.strftime(fmt)]
            url = parsed._replace(query=urlencode(query, doseq=True)).geturl()
    text = ensure_text(_pkg.http_get(url, name=source))
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("%s returned invalid JSON", source)
        return []
    records = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(records, list):
        return []
    out: List[Indicator] = []

    def extract_severity(entry: Dict[str, Any]) -> Optional[str]:
        metrics = entry.get("metrics", {})
        if not isinstance(metrics, dict):
            return None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            items = metrics.get(key)
            if not isinstance(items, list):
                continue
            for metric in items:
                if not isinstance(metric, dict):
                    continue
                if key == "cvssMetricV2":
                    sev = metric.get("baseSeverity")
                    if isinstance(sev, str):
                        return sev.lower()
                cvss = metric.get("cvssData")
                if isinstance(cvss, dict):
                    sev = cvss.get("baseSeverity")
                    if isinstance(sev, str):
                        return sev.lower()
        return None

    for item in records:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str):
            continue
        published = parse_dt(cve.get("published"))
        last_modified = parse_dt(cve.get("lastModified"))
        first_seen = published or last_modified or now
        if first_seen and first_seen < ws:
            continue
        description = ""
        for desc in cve.get("descriptions", []) or []:
            if isinstance(desc, dict) and desc.get("lang", "").lower() == "en":
                value = desc.get("value")
                if isinstance(value, str):
                    description = value.strip()
                    break
        severity = extract_severity(cve)
        tags = {"cve", "nvd"}
        if severity:
            tags.add(severity.lower())
        context = description or "NVD recent CVE"
        out.append(
            Indicator(
                indicator=cve_id.upper(),
                type="cve",
                source=source,
                first_seen=iso(first_seen or now),
                last_seen=iso(last_modified or first_seen or now),
                confidence="high",
                tlp="CLEAR",
                tags=",".join(sorted(tags)),
                reference=ref_url or "",
                context=context,
            )
        )
    return out


@register_parser("urlhaus")
def fetch_urlhaus_csv(url: str, ref_url: str, source: str, ws: datetime, *, status_filter: str = "any") -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):
            continue
        try:
            dateadded = parse_dt(row[1])
            url_val = row[2]
            url_status = (row[3] if len(row) > 3 else "").lower()
            threat = row[4] if len(row) > 4 else ""
        except Exception:
            continue
        if status_filter != "any" and url_status != status_filter:
            continue
        if dateadded and dateadded < ws:
            continue
        t = classify(url_val) or "url"
        out.append(
            Indicator(
                indicator=defang_min(url_val), type=t, source=source,
                first_seen=iso(dateadded or now), last_seen=iso(now),
                confidence="medium", tlp="CLEAR",
                tags=",".join(filter(None, ["malware", threat])),
                reference=ref_url or "", context=f"URLhaus: {threat}",
            )
        )
    return out


@register_parser("malwarebazaar")
def fetch_malwarebazaar_csv(
    url: str,
    ref_url: str,
    source: str,
    ws: datetime,
    *,
    fallback_url: Optional[str] = None,
    graceful_404: bool = False,
) -> List[Indicator]:
    try:
        text = ensure_text(_pkg.http_get(url, name=source))
    except Exception as e:
        if not isinstance(e, requests.exceptions.HTTPError):
            raise
        resp = getattr(e, "response", None)
        status = getattr(resp, "status_code", None)
        if resp is not None and status == 404 and fallback_url:
            logger.warning("%s 404, falling back to %s", url, fallback_url)
            text = ensure_text(_pkg.http_get(fallback_url, name=f"{source}_fallback"))
        elif resp is not None and status == 404 and graceful_404:
            logger.warning("%s 404, treating as empty due to --grace-on-404", url)
            return []
        else:
            raise
    out: List[Indicator] = []
    now = now_utc()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):
            continue
        try:
            first_seen = parse_dt(row[0].strip())
            sha256 = (row[3] if len(row) > 3 else "").strip().strip('"')
            sig_raw = ""
            if len(row) > 8:
                sig_raw = row[8]
            elif len(row) > 7:
                sig_raw = row[7]
            sig = sig_raw.strip().strip('"')
            if sig.lower() in {"", "n/a", "na", "none"}:
                sig = ""
        except Exception:
            continue
        if not sha256:
            continue
        if first_seen and first_seen < ws:
            continue
        out.append(
            Indicator(
                indicator=sha256.lower(), type="sha256", source=source,
                first_seen=iso(first_seen or now), last_seen=iso(now),
                confidence="medium", tlp="CLEAR",
                tags=",".join(filter(None, ["malware", sig])),
                reference=ref_url or "", context=f"MalwareBazaar: {sig}",
            )
        )
    return out


@register_parser("threatfox_recent", "threatfox_export_json")
def fetch_threatfox_export_json(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    raw = json.loads(text)
    data: List[Dict[str, Any]]
    if isinstance(raw, dict):
        if isinstance(raw.get("data"), list):
            # API POST response shape: {"query_status": ..., "data": [...]}
            data = [row for row in raw["data"] if isinstance(row, dict)]
        else:
            # Export endpoint shape: {"<ioc_id>": [entry, ...], ...}
            data = [
                entry
                for value in raw.values()
                if isinstance(value, list)
                for entry in value
                if isinstance(entry, dict)
            ]
    elif isinstance(raw, list):
        data = [row for row in raw if isinstance(row, dict)]
    else:
        data = []
    now = now_utc()
    out: List[Indicator] = []
    tmap = {
        "ipv4": "ipv4", "ipv6": "ipv6", "domain": "domain", "url": "url",
        "md5": "md5", "sha1": "sha1", "sha256": "sha256",
        # Export endpoint spellings.
        "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256",
        "sha512_hash": "sha512",
    }

    def normalise_tags(value: Any) -> List[str]:
        if isinstance(value, str):
            return [t.strip() for t in value.split(",") if t.strip()]
        if isinstance(value, (list, tuple)):
            return [str(t).strip() for t in value if str(t).strip()]
        return []

    for row in data:
        ioc = row.get("ioc") or row.get("ioc_value")
        if not isinstance(ioc, str) or not ioc.strip():
            continue
        ioc = ioc.strip()
        itype = (row.get("ioc_type") or "").lower()
        seen = parse_dt(row.get("first_seen") or row.get("first_seen_utc"))
        if seen and seen < ws:
            continue
        if itype == "ip:port":
            # "1.2.3.4:443" -> classify the bare address; keeps the value
            # comparable with other IP feeds so corroboration can match.
            host = ioc.rsplit(":", 1)[0]
            t = classify(host)
            if t not in {"ipv4", "ipv6"}:
                continue
            ioc = host
        else:
            t = tmap.get(itype)
            if not t:
                continue
        # ThreatFox reports 0-100 confidence_level; map onto our bands.
        level = row.get("confidence_level")
        if isinstance(level, (int, float)):
            confidence = "high" if level >= 75 else "medium" if level >= 40 else "low"
        else:
            confidence = "medium"
        val = defang_min(ioc) if t in {"url", "domain", "ipv4", "ipv6"} else ioc
        tags = normalise_tags(row.get("tags"))
        out.append(
            Indicator(
                indicator=val, type=t, source=source,
                first_seen=iso(seen or now), last_seen=iso(now),
                confidence=confidence, tlp="CLEAR",
                tags=",".join(sorted(set(["threatfox"] + tags))),
                reference=ref_url or "",
                context=row.get("malware_printable") or row.get("malware") or row.get("threat_type") or "ThreatFox recent",
            )
        )
    return out


@register_parser("feodo_ipblocklist")
def fetch_feodo_ipblocklist(
    url: str,
    ref_url: str,
    source: str,
    ws: datetime,
    *,
    disable_window: bool = True,
) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()

    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue

        header_token = row[0].strip().lower()
        if header_token.startswith("#") or header_token in {"first_seen_utc", "timestamp"}:
            continue

        try:
            seen = parse_dt(row[0])
            ip = row[1].strip()
            family = row[5].strip() if len(row) > 5 else ""
        except Exception:
            continue

        if not disable_window and seen and seen < ws:
            continue

        out.append(
            Indicator(
                indicator=defang_min(ip),
                type="ipv4",
                source=source,
                first_seen=iso(seen or now),
                last_seen=iso(now),
                confidence="high",
                tlp="CLEAR",
                tags=",".join(filter(None, ["feodo", "c2", family])),
                reference=ref_url or "",
                context="Feodo Tracker C2 IP",
            )
        )

    return out


def _fetch_sslbl_ja3(
    url: str,
    ref_url: str,
    source: str,
    ws: datetime,
    *,
    kind: str,
    disable_window: bool = True,
) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()

    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue

        # abuse.ch SSLBL CSV columns: ja3_md5, firstseen, lastseen, listingreason.
        # A valid JA3 hash in column 0 also filters out comment/header lines.
        ja = row[0].strip()
        if not JA3_RE.fullmatch(ja):
            continue

        first_seen = parse_dt(row[1]) if len(row) > 1 else None
        if not disable_window and first_seen and first_seen < ws:
            continue

        desc = (row[3].strip() if len(row) > 3 else "")

        out.append(
            Indicator(
                indicator=ja.lower(),
                type=("ja3" if kind == "ja3" else "ja3s"),
                source=source,
                first_seen=iso(first_seen or now),
                last_seen=iso(now),
                confidence="medium",
                tlp="CLEAR",
                tags=",".join(filter(None, ["sslbl", "tls", "fingerprint", desc])),
                reference=ref_url or "",
                context=f"SSLBL {('JA3' if kind == 'ja3' else 'JA3S')} fingerprint",
            )
        )

    return out


@register_parser("sslbl_ja3")
def fetch_sslbl_ja3(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    return _fetch_sslbl_ja3(url, ref_url, source, ws, kind="ja3")


@register_parser("spamhaus_drop")
def fetch_spamhaus_drop(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        cidr = line.split(";")[0].strip()
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}", cidr):
            continue
        out.append(
            Indicator(
                indicator=cidr, type="ipv4_cidr", source=source,
                first_seen=iso(now), last_seen=iso(now),
                confidence="high", tlp="CLEAR",
                tags="spamhaus,drop", reference=ref_url or "",
                context="Spamhaus DROP/EDROP network",
            )
        )
    return out


@register_parser("sslbl_ja3s")
def fetch_sslbl_ja3s(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    return _fetch_sslbl_ja3(url, ref_url, source, ws, kind="ja3s")


@register_parser("openphish")
def fetch_openphish(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for u in text.splitlines():
        u = u.strip()
        if not u or not re.match(r"^(?:https?://)", u, flags=re.I):
            continue
        out.append(
            Indicator(
                indicator=defang_min(u), type="url", source=source,
                first_seen=iso(now), last_seen=iso(now),
                confidence="medium", tlp="CLEAR",
                tags="phishing,openphish", reference=ref_url or "",
                context="OpenPhish feed",
            )
        )
    return out

@register_parser("cins_army")
def fetch_cins_army(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", line):
            out.append(
                Indicator(
                    indicator=defang_min(line), type="ipv4", source=source,
                    first_seen=iso(now), last_seen=iso(now),
                    confidence="low", tlp="CLEAR",
                    tags="cins,scanning,suspicious", reference=ref_url or "",
                    context="CINS Army IP",
                )
            )
    return out


@register_parser("tor_exit")
def fetch_tor_exit(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", line):
            out.append(
                Indicator(
                    indicator=defang_min(line),
                    type="ipv4",
                    source=source,
                    first_seen=iso(now),
                    last_seen=iso(now),
                    confidence="low",
                    tlp="CLEAR",
                    tags="tor,exit-node",
                    reference=ref_url or "",
                    context="Tor exit node list",
                )
            )

    return out


@register_parser("blocklist_txt")
def fetch_blocklist_txt(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(_pkg.http_get(url, name=source))
    now = now_utc()
    out: List[Indicator] = []
    seen: Set[Tuple[str, str]] = set()
    allowed_types = {"ipv4", "ipv6", "ipv4_cidr", "ipv6_cidr", "domain"}
    src_lower = source.lower()

    def derive_tags() -> Set[str]:
        tags = {"blocklist"}
        if "tor" in src_lower:
            tags.update({"tor", "exit-node"})
        if "ssh" in src_lower:
            tags.update({"ssh", "bruteforce"})
        if "greensnow" in src_lower:
            tags.add("greensnow")
        if "ci" in src_lower and "army" in src_lower:
            tags.update({"scanner", "cins"})
        if "compromised" in src_lower or "emergingthreats" in src_lower or src_lower.startswith("et_"):
            tags.update({"compromised", "emerging-threats"})
        if "binarydefense" in src_lower or "banlist" in src_lower:
            tags.update({"scanner", "binarydefense"})
        if "ipsum" in src_lower:
            tags.update({"aggregated", "ipsum", "multi-list"})
        return tags

    tags = derive_tags()
    confidence = "low" if "tor" in src_lower else "medium"

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.lower().startswith("exitaddress"):
            parts = line.split()
            tokens = parts[1:2]
        else:
            tokens = re.split(r"[\s,;]+", line)
        for token in tokens:
            token = token.strip()
            if not token:
                continue
            itype = classify(token)
            if itype not in allowed_types:
                continue
            value = defang_min(token) if itype in {"ipv4", "ipv6", "domain"} else token
            key = (itype, value)
            if key in seen:
                continue
            seen.add(key)
            out.append(
                Indicator(
                    indicator=value,
                    type=itype,
                    source=source,
                    first_seen=iso(now),
                    last_seen=iso(now),
                    confidence=confidence,
                    tlp="CLEAR",
                    tags=",".join(sorted(tags)),
                    reference=ref_url or "",
                    context=f"Blocklist entry from {source}",
                )
            )
    return out


@register_parser("rss")
def fetch_rss(url: str, ref_url: str, source: str, ws: datetime, *, per_entry_cap: int = 200, tolerate_missing: bool = False) -> List[Indicator]:
    try:
        fp = _pkg.load_feedparser()
    except SystemExit:
        if tolerate_missing:
            logger.warning("feedparser not available; skipping RSS for %s", source)
            return []
        raise
    try:
        feed = fp.parse(url, request_headers=choose_ua())
    except Exception as exc:
        logger.warning("RSS parse failed for %s: %s", source, exc)
        return []
    if getattr(feed, "bozo", 0) and getattr(feed, "bozo_exception", None):
        logger.debug("RSS %s reported a parse warning: %s", source, feed.bozo_exception)
    now = now_utc()
    out: List[Indicator] = []
    feed_updated = parse_dt(getattr(getattr(feed, "feed", object()), "updated", None)) or now
    for e in getattr(feed, "entries", []) or []:
        published = None
        for k in ("published", "updated"):
            value = getattr(e, k, None)
            if value:
                published = parse_dt(value)
                break
        if not published:
            published = feed_updated
        if published and published < ws:
            continue
        text_parts = [getattr(e, "title", ""), getattr(e, "summary", "")]
        for c in getattr(e, "content", []) or []:
            text_parts.append(c.get("value", ""))
        blob = "\n".join(filter(None, text_parts))
        found = extract_indicators_from_text(blob)
        if not found:
            continue
        seen: Set[Tuple[str, str]] = set()
        count = 0
        ref = getattr(e, "link", None) or ref_url or url
        for t, val in found:
            if count >= per_entry_cap:
                break
            k = (t, val)
            if k in seen:
                continue
            seen.add(k)
            count += 1
            val_out = defang_min(val) if t in {"url", "domain", "ipv4", "ipv6"} else val
            out.append(
                Indicator(
                    indicator=val_out, type=t, source=source,
                    first_seen=iso(published or now), last_seen=iso(now),
                    confidence="medium", tlp="CLEAR",
                    tags="blog,osint", reference=ref or "", context=f"RSS: {source}",
                )
            )
    return out


# ---------------- universal parser ----------------
@register_parser("universal", "auto", "generic", "phishstats")
def fetch_universal(
    url: str,
    ref_url: str,
    source: str,
    ws: datetime,
    *,
    assume_recent: bool = True,
    limit: Optional[int] = None,
) -> List[Indicator]:
    raw = _pkg.http_get(url, name=source)
    text = ensure_text(raw)
    now = now_utc()
    candidates: List[Tuple[str, str, Optional[datetime], Set[str], str]] = []

    def push_candidate(value: str, itype: str, seen: Optional[datetime], tags: Set[str], context: str) -> None:
        if limit is not None and len(candidates) >= limit:
            return
        if seen and seen < ws:
            return
        candidates.append((value, itype, seen, set(tags), context))

    def tagify(value: Any) -> Set[str]:
        tags: Set[str] = set()
        if isinstance(value, str):
            parts = re.split(r"[,;/\s]+", value)
            tags.update(t.strip().lower() for t in parts if t.strip())
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, str):
                    tags.update(tagify(item))
        return tags

    def derive_seen_from_dict(data: Dict[str, Any]) -> Optional[datetime]:
        for key, value in data.items():
            if not isinstance(value, str):
                continue
            if DATE_FIELD_RE.search(key):
                seen = parse_dt(value)
                if seen:
                    return seen
        return None

    def derive_tags_from_dict(data: Dict[str, Any]) -> Set[str]:
        tags: Set[str] = set()
        for key, value in data.items():
            if TAGS_FIELD_RE.search(key):
                tags.update(tagify(value))
        return tags

    def handle_text(blob: str, *, context: str, seen: Optional[datetime], tags: Set[str]) -> None:
        for itype, token in extract_indicators_from_text(blob):
            val = defang_min(token) if itype in {"url", "domain", "ipv4", "ipv6"} else token
            push_candidate(val, itype, seen, tags, context)

    def walk_json(
        node: Any,
        *,
        path: Tuple[str, ...] = (),
        inherited_seen: Optional[datetime] = None,
        inherited_tags: Optional[Set[str]] = None,
    ) -> None:
        tags = set(inherited_tags or set())
        seen = inherited_seen
        if isinstance(node, dict):
            seen = seen or derive_seen_from_dict(node)
            tags |= derive_tags_from_dict(node)
            for key, value in node.items():
                new_path = path + (str(key),)
                context = "/".join(new_path)
                if isinstance(value, str):
                    handle_text(value, context=context, seen=seen, tags=tags)
                elif isinstance(value, (list, tuple)):
                    walk_json(value, path=new_path, inherited_seen=seen, inherited_tags=tags)
                elif isinstance(value, dict):
                    walk_json(value, path=new_path, inherited_seen=seen, inherited_tags=tags)
                elif isinstance(value, (int, float)):
                    handle_text(str(value), context=context, seen=seen, tags=tags)
        elif isinstance(node, (list, tuple)):
            for idx, item in enumerate(node):
                walk_json(
                    item,
                    path=path + (f"[{idx}]",),
                    inherited_seen=inherited_seen,
                    inherited_tags=inherited_tags,
                )
        elif isinstance(node, str):
            handle_text(node, context="/".join(path) or source, seen=inherited_seen, tags=inherited_tags or set())
        elif isinstance(node, (int, float)):
            handle_text(str(node), context="/".join(path) or source, seen=inherited_seen, tags=inherited_tags or set())

    def parse_as_json() -> bool:
        try:
            data = json.loads(text)
        except Exception:
            return False
        walk_json(data, path=(source,))
        return True

    def parse_as_csv() -> bool:
        try:
            sample = "\n".join(text.splitlines()[:5])
            dialect = csv.Sniffer().sniff(sample) if sample else csv.excel
            reader = csv.reader(io.StringIO(text), dialect)
        except Exception:
            return False
        header: Optional[List[str]] = None
        for idx, row in enumerate(reader):
            if not row or all(not cell.strip() for cell in row):
                continue
            if header is None:
                header = [cell.strip() for cell in row]
                if any(classify(cell) for cell in header) or not any(re.search(r"[A-Za-z]", cell or "") for cell in header):
                    header = None
                else:
                    continue
            context_base = f"{source}[{idx}]"
            row_dict = {
                header[i] if header and i < len(header) else f"col{i}": row[i] for i in range(len(row))
            }
            seen = derive_seen_from_dict(row_dict) if isinstance(row_dict, dict) else None
            tags = derive_tags_from_dict(row_dict)
            for key, value in row_dict.items():
                if not isinstance(value, str):
                    continue
                handle_text(value, context=f"{context_base}/{key}", seen=seen, tags=tags)
        return True

    parsed = parse_as_json()
    if not parsed:
        parsed = parse_as_csv()
    if not parsed:
        handle_text(text, context=source, seen=None, tags=set())

    uniq: Dict[Tuple[str, str], Indicator] = {}
    for val, itype, seen, tags, context in candidates:
        if limit is not None and len(uniq) >= limit:
            break
        first_seen_dt = seen or (now if assume_recent else None)
        key = (itype, val)
        if key in uniq:
            indicator = uniq[key]
            existing_tags = set(filter(None, indicator.tags.split(",")))
            combined_tags = existing_tags | tags
            indicator.tags = ",".join(sorted(combined_tags))
            indicator.last_seen = iso(now)
            if seen:
                existing_first = parse_dt(indicator.first_seen)
                if existing_first is None or seen < existing_first:
                    indicator.first_seen = iso(seen)
            continue
        first_seen = first_seen_dt or now
        if first_seen < ws:
            continue
        uniq[key] = Indicator(
            indicator=val,
            type=itype,
            source=source,
            first_seen=iso(first_seen),
            last_seen=iso(now),
            confidence="medium",
            tlp="CLEAR",
            tags=",".join(sorted(t for t in tags if t)),
            reference=ref_url or "",
            context=context or source,
        )

    return list(uniq.values())


