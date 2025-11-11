#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import ipaddress
import inspect
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, cast

from collections.abc import Iterable as IterableABC

import requests
import yaml
from dateutil import parser as dtparser
import iocextract

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"

# ---------------- UA pool ----------------
DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.84 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
]
UA_POOL: List[str] = list(DEFAULT_UAS)

# --------------- runtime globals ---------------
logger = logging.getLogger("swiftioc")
_SESSION: Optional[requests.Session] = None
_FEEDPARSER = None
_SAVE_RAW_DIR: Optional[Path] = None
HTTP_DEBUG = False

CONF_RANK = {"low": 10, "medium": 50, "high": 90}


# ---------------- parser registry ----------------
ParserFunc = Callable[[str, str, str, datetime], List["Indicator"]]


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


# ---------------- models / utils ----------------
@dataclass
class Indicator:
    indicator: str
    type: str
    source: str
    first_seen: str
    last_seen: str
    confidence: str
    tlp: str
    tags: str
    reference: str
    context: str

    def key(self) -> Tuple[str, str]:
        return (self.type, self.indicator)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(ISO_FMT)


def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return dtparser.parse(s).astimezone(timezone.utc)
    except Exception:
        return None


def defang_min(text: str) -> str:
    text = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return text.replace(".", "[.]")


JA3_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")
EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.I)
BTC_RE = re.compile(r"^(?:bc1|[13])[A-Za-z0-9]{25,39}$")
BTC_INLINE_RE = re.compile(r"\b(?:bc1|[13])[A-Za-z0-9]{25,39}\b")
DATE_FIELD_RE = re.compile(r"(first|last)?_?(seen|time|date)|timestamp", re.I)
TAGS_FIELD_RE = re.compile(r"tags?|labels?|famil(?:y|ies)|threats?|malware|campaign", re.I)


def classify(v: str) -> Optional[str]:
    s = v.strip()
    try:
        ipaddress.ip_address(s)
        return "ipv6" if ":" in s else "ipv4"
    except Exception:
        pass
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                return "ipv4_cidr"
            return "ipv6_cidr"
    except Exception:
        pass
    if re.match(r"^(?:https?|ftp)://", s, flags=re.I):
        return "url"
    if re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\.?$", s):
        return "domain"
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", s):
        return "md5"
    if re.fullmatch(r"^[a-fA-F0-9]{40}$", s):
        return "sha1"
    if re.fullmatch(r"^[A-Fa-f0-9]{64}$", s):
        return "sha256"
    if SHA512_RE.fullmatch(s):
        return "sha512"
    if JA3_RE.fullmatch(s):
        return "ja3"
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", s, re.IGNORECASE):
        return "cve"
    if EMAIL_RE.fullmatch(s):
        return "email"
    if BTC_RE.fullmatch(s):
        return "btc_address"
    return None


def merge_conf(a: str, b: str) -> str:
    return a if CONF_RANK.get(a, 0) >= CONF_RANK.get(b, 0) else b


# ---------------- indicator extraction helpers ----------------
def _safe_iocextract(name: str, *args: Any, **kwargs: Any) -> Iterable[str]:
    func = getattr(iocextract, name, None)
    if not callable(func):
        return []
    try:
        result = func(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("iocextract %s failed: %s", name, exc)
        return []
    if isinstance(result, str) or not isinstance(result, IterableABC):
        return []
    return cast(Iterable[str], result)


def extract_indicators_from_text(blob: str) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []

    def push(token: str, *, fallback: Optional[str] = None, transform: Optional[Callable[[str], str]] = None) -> None:
        indicator_type = classify(token) or fallback
        if not indicator_type:
            return
        value = transform(token) if transform else token
        found.append((indicator_type, value))

    for url in _safe_iocextract("extract_urls", blob, refang=False):
        push(url, fallback="url")
    for ip in _safe_iocextract("extract_ips", blob):
        push(ip, fallback="ipv4")
    for ip in _safe_iocextract("extract_ipv6s", blob):  # type: ignore[attr-defined]
        push(ip, fallback="ipv6")
    for domain in _safe_iocextract("extract_domains", blob):  # type: ignore[attr-defined]
        push(domain, fallback="domain")
    for h in _safe_iocextract("extract_hashes", blob):
        push(h, fallback="sha256")
    for h in _safe_iocextract("extract_sha512_hashes", blob):  # type: ignore[attr-defined]
        push(h, fallback="sha512")
    for mail in _safe_iocextract("extract_emails", blob):  # type: ignore[attr-defined]
        push(mail, fallback="email")
    for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", blob, flags=re.I)):
        push(cve.upper(), fallback="cve")
    for ja3 in set(JA3_RE.findall(blob)):
        push(ja3.lower(), fallback="ja3")
    for btc in {m.group(0) for m in BTC_INLINE_RE.finditer(blob)}:
        push(btc, fallback="btc_address")
    return found


# ---------------- HTTP layer ----------------
def build_session() -> requests.Session:
    from urllib3.util import Retry
    from requests.adapters import HTTPAdapter
    s = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.6, status_forcelist=(429, 500, 502, 503, 504)))
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def ensure_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = build_session()
    return _SESSION


def choose_ua() -> Dict[str, str]:
    return {"User-Agent": random.choice(UA_POOL)}


def save_raw(name: str, content: str | bytes, kind: str) -> None:
    if not _SAVE_RAW_DIR:
        return
    try:
        _SAVE_RAW_DIR.mkdir(parents=True, exist_ok=True)
        p = _SAVE_RAW_DIR / f"{name}.{'txt' if kind == 'text' else 'bin'}"
        if kind == "text":
            data = content if isinstance(content, str) else content.decode("utf-8", errors="ignore")
            with p.open("w", encoding="utf-8") as f_text:
                f_text.write(data)
        else:
            payload = content.encode("utf-8") if isinstance(content, str) else content
            with p.open("wb") as f_bin:
                f_bin.write(payload)
    except Exception as e:
        logger.debug("raw-save-failed %s: %s", name, e)


def http_get(url: str, *, name: str, kind: str = "text", timeout: int = 30) -> str | bytes:
    s = ensure_session()
    headers = choose_ua()
    t0 = time.perf_counter()
    r = s.get(url, headers=headers, timeout=timeout)
    dt = time.perf_counter() - t0
    if HTTP_DEBUG:
        logger.debug("HTTP %s %.2fs %s [%s]", r.status_code, dt, url, name)
    r.raise_for_status()
    body = r.text if kind == "text" else r.content
    save_raw(name, body, kind)
    return body


def ensure_text(content: str | bytes) -> str:
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="ignore")
    return content


# --------------- Lazy RSS ----------------
def load_feedparser() -> Any:
    global _FEEDPARSER
    if _FEEDPARSER is not None:
        return _FEEDPARSER
    try:
        _FEEDPARSER = import_module("feedparser")
        return _FEEDPARSER
    except ModuleNotFoundError as e:
        raise SystemExit("Missing 'feedparser'. Install it or run with --skip-rss") from e


# --------------- adapters (no hard-coded refs) ---------------
@register_parser("kev", "cisa_kev")
def fetch_cisa_kev(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    data = json.loads(http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for it in data.get("vulnerabilities", []) or []:
        cve = it.get("cveID")
        pub = parse_dt(it.get("dateAdded"))
        if not cve or (pub and pub < ws):
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
    text = ensure_text(http_get(url, name=source))
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("%s returned invalid JSON", source)
        return []
    records = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(records, list):
        return []
    now = now_utc()
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
    text = ensure_text(http_get(url, name=source))
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
        text = ensure_text(http_get(url, name=source))
    except Exception as e:
        if not isinstance(e, requests.exceptions.HTTPError):
            raise
        resp = getattr(e, "response", None)
        status = getattr(resp, "status_code", None)
        if resp is not None and status == 404 and fallback_url:
            logger.warning("%s 404, falling back to %s", url, fallback_url)
            text = ensure_text(http_get(fallback_url, name=f"{source}_fallback"))
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
    text = ensure_text(http_get(url, name=source))
    raw = json.loads(text)
    if isinstance(raw, dict):
        data = raw.get("data") or []
    else:
        data = raw
    now = now_utc()
    out: List[Indicator] = []
    tmap = {"ipv4": "ipv4", "ipv6": "ipv6", "domain": "domain", "url": "url", "md5": "md5", "sha1": "sha1", "sha256": "sha256"}

    for row in data or []:
        ioc = row.get("ioc")
        itype = (row.get("ioc_type") or "").lower()
        seen = parse_dt(row.get("first_seen"))
        if not ioc or (seen and seen < ws):
            continue
        t = tmap.get(itype)
        if not t:
            continue
        val = defang_min(ioc) if t in {"url", "domain", "ipv4", "ipv6"} else ioc
        tags = row.get("tags") or []
        out.append(
            Indicator(
                indicator=val, type=t, source=source,
                first_seen=iso(seen or now), last_seen=iso(now),
                confidence="medium", tlp="CLEAR",
                tags=",".join(sorted(set(["threatfox"] + tags))),
                reference=ref_url or "",
                context=row.get("malware") or row.get("threat_type") or "ThreatFox recent",
            )
        )
    return out


@register_parser("feodo_ipblocklist")
def fetch_feodo_ipblocklist(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(http_get(url, name=source))
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
        if seen and seen < ws:
            continue
        out.append(
            Indicator(
                indicator=defang_min(ip), type="ipv4", source=source,
                first_seen=iso(seen or now), last_seen=iso(now),
                confidence="high", tlp="CLEAR",
                tags=",".join(filter(None, ["feodo", "c2", family])),
                reference=ref_url or "", context="Feodo Tracker C2 IP",
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
) -> List[Indicator]:
    text = ensure_text(http_get(url, name=source))
    out: List[Indicator] = []
    now = now_utc()
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        header_token = row[0].strip().lower()
        if header_token.startswith("#") or header_token in {"first_seen", "timestamp"}:
            continue
        ja = row[1].strip() if len(row) > 1 else None
        if not ja:
            continue
        if not JA3_RE.fullmatch(ja.strip()):
            # Skip malformed entries and ensure we only publish valid JA3 hashes
            continue
        first_seen = parse_dt(row[0]) if row[0] else None
        if first_seen and first_seen < ws:
            continue
        desc = row[2] if len(row) > 2 else ""
        out.append(
            Indicator(
                indicator=ja.lower(), type=("ja3" if kind == "ja3" else "ja3s"), source=source,
                first_seen=iso(first_seen or now), last_seen=iso(now),
                confidence="medium", tlp="CLEAR",
                tags=",".join(filter(None, ["sslbl", "tls", "fingerprint", desc])),
                reference=ref_url or "", context=f"SSLBL {('JA3' if kind=='ja3' else 'JA3S')} fingerprint",
            )
        )
    return out


@register_parser("sslbl_ja3")
def fetch_sslbl_ja3(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    return _fetch_sslbl_ja3(url, ref_url, source, ws, kind="ja3")


@register_parser("spamhaus_drop")
def fetch_spamhaus_drop(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(http_get(url, name=source))
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
    text = ensure_text(http_get(url, name=source))
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


@register_parser("phishstats")
def fetch_phishstats(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(http_get(url, name=source))
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("%s returned invalid JSON", source)
        return []
    if isinstance(payload, list):
        records: Iterable[Any] = payload
    elif isinstance(payload, dict):
        records = payload.get("data") or []
    else:
        return []
    now = now_utc()
    out: List[Indicator] = []

    def choose(row: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
        for key in keys:
            val = row.get(key)
            if isinstance(val, str) and val.strip():
                return val
        return None

    for row in records:
        if not isinstance(row, dict):
            continue
        url_val = choose(row, ("url", "phish_url", "phishURL", "phish_url_https"))
        if not url_val:
            continue
        seen = parse_dt(choose(row, ("date", "first_seen", "submission_time", "created_at")))
        if seen and seen < ws:
            continue
        tags = {"phishing", "phishstats"}
        target = choose(row, ("target", "brand", "campaign"))
        if target:
            tags.add(target.lower())
        context_parts = ["PhishStats entry"]
        if target:
            context_parts.append(target)
        context = ": ".join(context_parts)
        ref = choose(row, ("phish_detail_url", "detail_url", "source")) or ref_url or ""
        out.append(
            Indicator(
                indicator=defang_min(url_val),
                type="url",
                source=source,
                first_seen=iso(seen or now),
                last_seen=iso(now),
                confidence="medium",
                tlp="CLEAR",
                tags=",".join(sorted(tags)),
                reference=ref,
                context=context,
            )
        )
        ip_val = choose(row, ("ip", "ip_address", "resolved_ip"))
        if ip_val and classify(ip_val) in {"ipv4", "ipv6"}:
            indicator_type = "ipv6" if ":" in ip_val else "ipv4"
            out.append(
                Indicator(
                    indicator=defang_min(ip_val),
                    type=indicator_type,
                    source=source,
                    first_seen=iso(seen or now),
                    last_seen=iso(now),
                    confidence="medium",
                    tlp="CLEAR",
                    tags=",".join(sorted(tags | {"infrastructure"})),
                    reference=ref,
                    context=f"PhishStats infrastructure for {url_val}",
                )
            )
    return out


@register_parser("cins_army")
def fetch_cins_army(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(http_get(url, name=source))
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
    text = ensure_text(http_get(url, name=source))
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
                    tags="tor,exit-node", reference=ref_url or "",
                    context="Tor exit node list",
                )
        )
    return out


@register_parser("blocklist_txt")
def fetch_blocklist_txt(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = ensure_text(http_get(url, name=source))
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
        fp = load_feedparser()
    except SystemExit:
        if tolerate_missing:
            logger.warning("feedparser not available; skipping RSS for %s", source)
            return []
        raise
    try:
        feed = fp.parse(url, request_headers=choose_ua())
    except Exception:
        return []
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
@register_parser("universal", "auto", "generic")
def fetch_universal(
    url: str,
    ref_url: str,
    source: str,
    ws: datetime,
    *,
    assume_recent: bool = True,
    limit: Optional[int] = None,
) -> List[Indicator]:
    raw = http_get(url, name=source)
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


# ---------------- collect / orchestrate ----------------
def parse_name_int_pairs(pairs: List[str], flag: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in pairs or []:
        if "=" in item:
            k, v = item.split("=", 1)
            try:
                out[k.strip()] = int(v.strip())
            except ValueError:
                logger.warning("Invalid %s pair: %s", flag, item)
    return out


def type_counts(items: List[Indicator]) -> Dict[str, int]:
    wanted = (
        "url",
        "domain",
        "ipv4",
        "ipv6",
        "ipv4_cidr",
        "ipv6_cidr",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "cve",
        "email",
        "btc_address",
        "ja3",
        "ja3s",
    )
    return {t: sum(1 for r in items if r.type == t) for t in wanted}


def type_breakdown(items: List[Indicator]) -> List[Tuple[str, int]]:
    bag: Dict[str, int] = {}
    for r in items:
        bag[r.type] = bag.get(r.type, 0) + 1
    return sorted(bag.items(), key=lambda kv: (-kv[1], kv[0]))


def top_tags(items: List[Indicator], n: int = 5) -> List[Tuple[str, int]]:
    bag: Dict[str, int] = {}
    for r in items:
        if not r.tags:
            continue
        for t in [x for x in r.tags.split(",") if x]:
            bag[t] = bag.get(t, 0) + 1
    return sorted(bag.items(), key=lambda kv: kv[1], reverse=True)[:n]


def collect_from_yaml(
    cfg: Dict[str, Any],
    window_hours: int,
    *,
    skip_rss: bool,
    max_per_source: Optional[int],
    urlhaus_status: str,
    source_window: Dict[str, int],
    grace_on_404: Set[str],
    ci_safe_rss: bool,
) -> Tuple[List[Indicator], Dict[str, int], Dict[str, Any]]:
    base_start = now_utc() - timedelta(hours=window_hours)

    def start_for(name: str) -> datetime:
        if name in source_window:
            return now_utc() - timedelta(hours=source_window[name])
        return base_start

    def cap(xs: List[Indicator]) -> List[Indicator]:
        return xs[:max_per_source] if (max_per_source and len(xs) > max_per_source) else xs

    indicators: List[Indicator] = []
    counts: Dict[str, int] = {}
    failures: List[Dict[str, str]] = []
    raw_total = 0

    # APIs
    for api in cfg.get("apis", []) or []:
        name = api.get("name", "api")
        parse = api.get("parse")
        if not parse:
            continue
        url = api.get("url", "")
        ref = api.get("reference", url) or ""
        ws = start_for(name)
        got: List[Indicator] = []
        try:
            t0 = time.perf_counter()
            parser_fn = resolve_parser(parse)
            parser_sig = inspect.signature(parser_fn)
            supported_kwargs = {
                k
                for k in parser_sig.parameters
                if k not in {"url", "ref_url", "source", "ws"}
            }
            options: Dict[str, Any] = dict(api.get("options", {}))
            for key in ("fallback_url", "graceful_404", "status_filter"):
                if key in api and key not in options:
                    options[key] = api[key]
            if name in grace_on_404 and "graceful_404" in supported_kwargs:
                options.setdefault("graceful_404", True)
            if "status_filter" in supported_kwargs:
                options.setdefault("status_filter", urlhaus_status)
            filtered_options = {k: v for k, v in options.items() if k in supported_kwargs}
            got = parser_fn(url, ref, name, ws, **filtered_options)
            dt = time.perf_counter() - t0
            logger.debug("collect %s %d in %.2fs", name, len(got), dt)
            logger.debug("summary %s types=%s tags_top=%s", name, type_counts(got), top_tags(got))
        except Exception as e:
            logger.warning("%s failed: %s", name, e)
            failures.append({"source": name, "error": str(e)})
            got = []
        got = cap(got)
        raw_total += len(got)
        indicators.extend(got)
        counts[name] = len(got)

    # RSS
    if not skip_rss:
        for rss in cfg.get("rss", []) or []:
            name = rss.get("name", "rss")
            url = rss.get("url")
            if not url:
                continue
            ref = rss.get("reference", url) or ""
            try:
                t0 = time.perf_counter()
                got = fetch_rss(url, ref, name, start_for(name), tolerate_missing=ci_safe_rss)
                dt = time.perf_counter() - t0
                logger.debug("collect RSS %s %d in %.2fs", name, len(got), dt)
                logger.debug("summary %s types=%s tags_top=%s", name, type_counts(got), top_tags(got))
            except Exception as e:
                logger.warning("%s failed: %s", name, e)
                failures.append({"source": name, "error": str(e)})
                got = []
            got = cap(got)
            raw_total += len(got)
            indicators.extend(got)
            counts[name] = len(got)

    # Dedup + merge
    uniq: Dict[Tuple[str, str], Indicator] = {}
    for i in indicators:
        k = i.key()
        if k not in uniq:
            uniq[k] = i
            continue
        prev = uniq[k]
        # last_seen
        try:
            p = parse_dt(prev.last_seen) or now_utc()
            n = parse_dt(i.last_seen) or now_utc()
            prev.last_seen = iso(n if n > p else p)
        except Exception:
            prev.last_seen = max(prev.last_seen, i.last_seen)
        # confidence/tags/source merge
        prev.confidence = merge_conf(prev.confidence, i.confidence)
        merged_tags = set(filter(None, prev.tags.split(","))) | set(filter(None, i.tags.split(",")))
        prev.tags = ",".join(sorted(t.strip().strip('"') for t in merged_tags if t))
        if i.source not in prev.source.split(","):
            prev.source = ",".join(sorted(set(prev.source.split(",")) | set(i.source.split(","))))
    final = sorted(uniq.values(), key=lambda r: (r.type, r.indicator, r.source))
    stats: Dict[str, Any] = {
        "raw_total": raw_total,
        "failures": failures,
    }
    return final, counts, stats


# ---------------- writers ----------------
def write_csv(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["indicator", "type", "source", "first_seen", "last_seen", "confidence", "tlp", "tags", "reference", "context"])
        for r in rows:
            w.writerow([r.indicator, r.type, r.source, r.first_seen, r.last_seen, r.confidence, r.tlp, r.tags, r.reference, r.context])


def write_tsv(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["indicator", "type", "source", "first_seen", "last_seen", "confidence", "tlp", "tags", "reference", "context"])
        for r in rows:
            w.writerow([r.indicator, r.type, r.source, r.first_seen, r.last_seen, r.confidence, r.tlp, r.tags, r.reference, r.context])


def write_json(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in rows], f, ensure_ascii=False, indent=2)


def write_jsonl(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")


def write_stix(path: Path, rows: List[Indicator]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = iso(now_utc())
    objects = []
    for r in rows:
        pattern = None
        if r.type in {"ipv4", "ipv6"}:
            pattern = f"[ipv4-addr:value = '{r.indicator.replace('[.]', '.')}']" if r.type == "ipv4" else f"[ipv6-addr:value = '{r.indicator}']"
        elif r.type == "domain":
            pattern = f"[domain-name:value = '{r.indicator.replace('[.]', '.')}']"
        elif r.type == "url":
            p = r.indicator.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".")
            pattern = f"[url:value = '{p}']"
        elif r.type in {"md5", "sha1", "sha256"}:
            pattern = f"[file:hashes.'{r.type}' = '{r.indicator}']"
        elif r.type == "cve":
            pattern = f"[vulnerability:name = '{r.indicator}']"
        if not pattern:
            continue
        sid = hashlib.sha256((r.type + r.indicator).encode()).hexdigest()[:32]
        objects.append(
            {
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{sid}", "created": now, "modified": now,
                "name": f"{r.type}:{r.indicator}", "pattern": pattern, "pattern_type": "stix",
                "valid_from": r.first_seen, "confidence": 70 if r.confidence == "high" else 50 if r.confidence == "medium" else 30,
                "labels": [t for t in r.tags.split(",") if t],
                "x_swiftioc_source": r.source, "x_swiftioc_tlp": r.tlp, "x_swiftioc_reference": r.reference,
            }
        )
    bundle = {"type": "bundle", "id": "bundle--" + hashlib.sha1(now.encode()).hexdigest(), "objects": objects}
    with path.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)


def write_changelog(path: Path, counts: Dict[str, int], total: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ts = iso(now_utc())
    lines = ["# Changelog", "", f"## {ts}", "", f"Total indicators: **{total}**", "", "### By source"]
    lines.extend(f"- {k}: {v}" for k, v in sorted(counts.items()))
    lines.append("")
    with path.open("a", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------- logging ----------------
class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": iso(now_utc()), "level": record.levelname, "name": record.name, "msg": record.getMessage()}
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(console_level: int, *, log_file: Optional[Path], file_level: int, fmt: str) -> None:
    logger.setLevel(min(console_level, file_level))
    for h in list(logger.handlers):
        logger.removeHandler(h)
    ch = logging.StreamHandler()
    ch.setLevel(console_level)
    ch.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
    logger.addHandler(ch)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(file_level)
        fh.setFormatter(JsonLineFormatter() if fmt == "json" else logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
        logger.addHandler(fh)


def _load_ua_file(path: Optional[Path]) -> None:
    if not path:
        return
    if not path.exists():
        logger.warning("UA file not found: %s", path)
        return
    try:
        pool = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
        if pool:
            UA_POOL.clear()
            UA_POOL.extend(pool)
            logger.info("Loaded %d User-Agents from %s", len(pool), path)
    except Exception as e:
        logger.warning("Failed loading UA file: %s", e)


# ---------------- small helpers ----------------
def gh_summary_path() -> Optional[Path]:
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(p) if p else None


def append_gh_summary(lines: List[str]) -> None:
    p = gh_summary_path()
    if not p:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


def _self_tests() -> int:
    assert classify("1.2.3.4") == "ipv4"
    assert classify("2001:db8::1") == "ipv6"
    assert classify("https://x.com") == "url"
    assert classify("example.com") == "domain"
    assert classify("CVE-2025-12345") == "cve"
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert classify("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    df = defang_min("https://a.b")
    assert df.startswith("hxxps://") and "[.]" in df
    print("Self-tests passed.")
    return 0


# ---------------- CLI ----------------
def main() -> int:
    ap = argparse.ArgumentParser(description="SwiftIOC — collect IOCs from YAML-defined sources (CI-friendly)")
    ap.add_argument("--out-dir", type=Path, default=Path("public"))
    ap.add_argument("--sources", type=Path, default=Path("sources.yml"))
    ap.add_argument("--window-hours", type=int, default=48)
    ap.add_argument("--skip-rss", action="store_true")
    ap.add_argument("--max-per-source", type=int, default=None)
    ap.add_argument("--urlhaus-status", choices=["any", "online", "offline"], default="any")
    ap.add_argument("--source-window", action="append", default=[], help="Override lookback per source: name=HOURS")
    ap.add_argument("--fail-on-empty", nargs="*", default=None, help="Fail if any listed sources return zero")
    ap.add_argument("--fail-if-stale", action="append", default=[], help="Fail if source newest first_seen older than HOURS: name=HOURS")
    ap.add_argument("--grace-on-404", action="append", default=[], help="Treat 404 on these sources as empty but non-fatal: name")

    # logging / diag
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("--log-file", type=Path, default=None)
    ap.add_argument("--log-format", choices=["text", "json"], default="text")
    ap.add_argument("--log-file-level", choices=["ERROR", "WARNING", "INFO", "DEBUG"], default="DEBUG")
    ap.add_argument("--save-raw-dir", type=Path, default=None)
    ap.add_argument("--diag-json", type=Path, default=Path("public/diagnostics/run.json"))
    ap.add_argument("--report", type=Path, default=Path("public/diagnostics/REPORT.md"))
    ap.add_argument("--ua-file", type=Path, default=None, help="Optional file with one UA per line")

    # CI helpers
    ap.add_argument("--ci-safe", action="store_true", help="CI convenience: JSON logs, ensure diagnostics dirs, tolerate missing RSS dep")

    ap.add_argument("--self-test", action="store_true")

    args = ap.parse_args()

    if args.self_test:
        return _self_tests()

    # CI-aware tweaks
    on_ci = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    if args.ci_safe:
        args.log_format = "json"
        if not args.save_raw_dir:
            args.save_raw_dir = Path("public/diagnostics/raw")
        args.skip_rss = args.skip_rss  # unchanged, but RSS will tolerate missing dep
    if on_ci and args.verbose == 0:
        # default to INFO on CI to get more signal in logs
        args.verbose = 1

    # logging
    console_level = logging.WARNING
    if args.verbose == 1:
        console_level = logging.INFO
    elif args.verbose >= 2:
        console_level = logging.DEBUG
    file_level = getattr(logging, args.log_file_level, logging.DEBUG) if isinstance(args.log_file_level, str) else logging.DEBUG
    configure_logging(console_level, log_file=args.log_file, file_level=file_level, fmt=args.log_format)

    global _SAVE_RAW_DIR, HTTP_DEBUG
    _SAVE_RAW_DIR = args.save_raw_dir
    HTTP_DEBUG = (console_level == logging.DEBUG or file_level == logging.DEBUG)

    # UA file
    _load_ua_file(args.ua_file)

    # Ensure diagnostics dirs (nice for GH Artifacts)
    if args.diag_json:
        args.diag_json.parent.mkdir(parents=True, exist_ok=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
    if _SAVE_RAW_DIR:
        _SAVE_RAW_DIR.mkdir(parents=True, exist_ok=True)

    # YAML (auto fallback to example)
    if not args.sources.exists():
        ex = Path("sources.example.yml")
        if ex.exists():
            logger.warning("Sources file %s not found; using %s", args.sources, ex)
            args.sources = ex
        else:
            logger.error("Sources file not found: %s", args.sources)
            return 1
    with args.sources.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    # collect
    rows, counts, stats = collect_from_yaml(
        cfg,
        window_hours=args.window_hours,
        skip_rss=args.skip_rss,
        max_per_source=args.max_per_source,
        urlhaus_status=args.urlhaus_status,
        source_window=parse_name_int_pairs(args.source_window, "--source-window"),
        grace_on_404=set(args.grace_on_404 or []),
        ci_safe_rss=args.ci_safe,
    )

    # outputs
    out_dir: Path = args.out_dir
    write_csv(out_dir / "iocs" / "latest.csv", rows)
    write_tsv(out_dir / "iocs" / "latest.tsv", rows)
    write_json(out_dir / "iocs" / "latest.json", rows)
    write_jsonl(out_dir / "iocs" / "latest.jsonl", rows)
    write_stix(out_dir / "iocs" / "stix2.json", rows)
    write_changelog(out_dir / "changelog" / "CHANGELOG.md", counts, total=len(rows))

    # diagnostics / summary
    run_ts = iso(now_utc())
    type_totals = type_breakdown(rows)
    first_seen_dates: List[datetime] = []
    for r in rows:
        dt = parse_dt(r.first_seen)
        if dt:
            first_seen_dates.append(dt)
    earliest = iso(min(first_seen_dates)) if first_seen_dates else None
    latest = iso(max(first_seen_dates)) if first_seen_dates else None
    raw_total = stats.get("raw_total", len(rows))
    duplicates_removed = max(raw_total - len(rows), 0)
    empty_sources = sorted([name for name, count in counts.items() if count == 0])
    diag = {
        "window_hours": args.window_hours,
        "total": len(rows),
        "total_before_dedup": raw_total,
        "duplicates_removed": duplicates_removed,
        "counts": counts,
        "type_counts": {k: v for k, v in type_totals},
        "earliest_first_seen": earliest,
        "newest_first_seen": latest,
        "empty_sources": empty_sources,
        "failures": stats.get("failures", []),
        "version": 2,
        "ts": run_ts,
    }
    if args.diag_json:
        args.diag_json.write_text(json.dumps(diag, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.report:
        report_lines: List[str] = [
            "# SwiftIOC Run Report",
            "",
            "## Overview",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Generated | {run_ts} |",
            f"| Window (hours) | {args.window_hours} |",
            f"| Total indicators | {len(rows)} |",
            f"| Duplicates removed | {duplicates_removed} |",
        ]
        if earliest:
            report_lines.append(f"| Earliest first_seen | {earliest} |")
        if latest:
            report_lines.append(f"| Newest first_seen | {latest} |")
        report_lines.append("")
        report_lines.extend(["## Per-source counts", ""])
        report_lines.append("| Source | Indicators |")
        report_lines.append("| --- | ---: |")
        if counts:
            for name, count in sorted(counts.items()):
                report_lines.append(f"| {name} | {count} |")
        else:
            report_lines.append("| _None_ | 0 |")
        report_lines.append("")
        if type_totals:
            report_lines.extend(["## Indicator types", "", "| Type | Indicators |", "| --- | ---: |"])
            for t, count in type_totals:
                report_lines.append(f"| {t} | {count} |")
            report_lines.append("")
        issues: List[str] = []
        for failure in stats.get("failures", []):
            src = failure.get("source", "unknown")
            err = failure.get("error", "")
            issues.append(f"- ⚠️ **{src}**: {err}")
        for src in empty_sources:
            issues.append(f"- ⚠️ **{src}** returned zero indicators")
        if issues:
            report_lines.extend(["## Issues", "", *issues, ""])
        args.report.write_text("\n".join(report_lines), encoding="utf-8")

    # Append a brief GH step summary (if available)
    summary_lines: List[str] = [
        "### SwiftIOC",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total indicators | {len(rows)} |",
        f"| Duplicates removed | {duplicates_removed} |",
    ]
    if earliest:
        summary_lines.append(f"| Earliest first_seen | {earliest} |")
    if latest:
        summary_lines.append(f"| Newest first_seen | {latest} |")
    summary_lines.extend([
        "",
        "#### Per-source counts",
        "",
        "| Source | Indicators |",
        "| --- | ---: |",
    ])
    if counts:
        for name, count in sorted(counts.items()):
            summary_lines.append(f"| {name} | {count} |")
    else:
        summary_lines.append("| _None_ | 0 |")
    if type_totals:
        summary_lines.extend([
            "",
            "#### Indicator types",
            "",
            "| Type | Indicators |",
            "| --- | ---: |",
        ])
        for t, count in type_totals:
            summary_lines.append(f"| {t} | {count} |")
    issues_summary: List[str] = []
    for failure in stats.get("failures", []):
        src = failure.get("source", "unknown")
        err = failure.get("error", "")
        issues_summary.append(f"- ⚠️ **{src}**: {err}")
    for src in empty_sources:
        issues_summary.append(f"- ⚠️ **{src}** returned zero indicators")
    if issues_summary:
        summary_lines.extend(["", "#### Issues", "", *issues_summary])
    summary_lines.append("")
    append_gh_summary(summary_lines)

    # guardrails
    if args.fail_on_empty:
        empty = [s for s in args.fail_on_empty if counts.get(s, 0) == 0]
        if empty:
            logger.error("Failing due to empty sources: %s", empty)
            return 1

    stale_cfg = parse_name_int_pairs(args.fail_if_stale, "--fail-if-stale")
    if stale_cfg:
        newest: Dict[str, Optional[datetime]] = {}
        for r in rows:
            dt = parse_dt(r.first_seen)
            if dt is None:
                continue
            cur = newest.get(r.source)
            if cur is None or dt > cur:
                newest[r.source] = dt
        too_old: List[str] = []
        now = now_utc()
        for name, hours in stale_cfg.items():
            limit = now - timedelta(hours=hours)
            n = newest.get(name)
            if n is None or n < limit:
                too_old.append(name)
        if too_old:
            logger.error("Failing due to stale sources: %s", too_old)
            return 1

    if args.skip_rss:
        logger.info("RSS skipped — install 'feedparser' to enable RSS")
    logger.info("Wrote %d indicators to %s/iocs", len(rows), out_dir)
    logger.info("Per-source counts: %s", dict(counts))
    return 0


if __name__ == "__main__":
    import sys
    rc = main()
    if rc:
        sys.exit(rc)
