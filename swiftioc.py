#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import io
import ipaddress
import inspect
import json
import logging
import os
import random
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, fields as dataclass_fields
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
    # Computed 0-100 relevance score (confidence base + cross-source
    # corroboration bonus, decayed by age). 0 means "not yet scored".
    score: int = 0

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


def refang(text: str) -> str:
    """Reverse :func:`defang_min` so a value can be matched or emitted raw."""
    return (
        text.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
    )


_URL_HEAD_RE = re.compile(r"^(hxxps?|https?|ftp)(://)([^/]+)(.*)$", re.I)


def _lower_authority_host(authority: str) -> str:
    """Lowercase only the host portion of a URL authority component.

    ``authority`` is ``[userinfo@]host[:port]``. Userinfo (which may carry a
    case-sensitive username/password/token) is preserved verbatim; only the
    host — and an IPv6 literal's brackets — are lowercased.
    """
    userinfo, at, hostport = authority.rpartition("@") if "@" in authority else ("", "", authority)
    if hostport.startswith("["):
        end = hostport.find("]")
        if end != -1:
            return userinfo + at + hostport[: end + 1].lower() + hostport[end + 1 :]
        return userinfo + at + hostport.lower()
    host, sep, port = hostport.partition(":")
    return userinfo + at + host.lower() + sep + port


def normalize_value(itype: str, value: str) -> str:
    """Canonicalise host casing so equivalent indicators dedup together.

    Domains are lowercased entirely; URLs have only their scheme and host
    lowercased (userinfo, paths, and query strings are case-sensitive and left
    intact — lowercasing credentials would both mangle them and risk merging
    distinct indicators during dedup).
    """
    if itype == "domain":
        return value.lower()
    if itype == "url":
        m = _URL_HEAD_RE.match(value)
        if m:
            return m.group(1).lower() + m.group(2) + _lower_authority_host(m.group(3)) + m.group(4)
    return value


JA3_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")
EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.I)
BTC_RE = re.compile(r"^(?:bc1|[13])[A-Za-z0-9]{25,39}$")
BTC_INLINE_RE = re.compile(r"\b(?:bc1|[13])[A-Za-z0-9]{25,39}\b")
DATE_FIELD_RE = re.compile(r"(first|last)?_?(seen|time|date)|timestamp", re.I)
TAGS_FIELD_RE = re.compile(r"tags?|labels?|famil(?:y|ies)|threats?|malware|campaign", re.I)

# Precompiled once at import time; classify() is the hottest function in the
# pipeline (called for every extracted token) so avoid recompiling per call.
URL_SCHEME_RE = re.compile(r"^(?:https?|ftp)://", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\.?$")
MD5_RE = re.compile(r"[a-fA-F0-9]{32}")
SHA1_RE = re.compile(r"[a-fA-F0-9]{40}")
SHA256_RE = re.compile(r"[A-Fa-f0-9]{64}")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


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
    if URL_SCHEME_RE.match(s):
        return "url"
    if DOMAIN_RE.match(s):
        return "domain"
    if MD5_RE.fullmatch(s):
        return "md5"
    if SHA1_RE.fullmatch(s):
        return "sha1"
    if SHA256_RE.fullmatch(s):
        return "sha256"
    if SHA512_RE.fullmatch(s):
        return "sha512"
    if JA3_RE.fullmatch(s):
        return "ja3"
    if CVE_RE.fullmatch(s):
        return "cve"
    if EMAIL_RE.fullmatch(s):
        return "email"
    if BTC_RE.fullmatch(s):
        return "btc_address"
    return None


def merge_conf(a: str, b: str) -> str:
    return a if CONF_RANK.get(a, 0) >= CONF_RANK.get(b, 0) else b


# ---------------- scoring: corroboration + age decay ----------------
# Base score by source-assigned confidence.
SCORE_BASE = {"low": 40, "medium": 60, "high": 80}
# Each independent source beyond the first adds a corroboration bonus: an IP
# reported by Feodo *and* ThreatFox *and* a blog post is qualitatively
# different from a single scanner hit.
CORROBORATION_BONUS = 8
CORROBORATION_CAP = 16
# Exponential decay half-life per indicator type, in hours. Network
# infrastructure churns fast (a C2 IP from a month ago is likely someone
# else's VPS today); file hashes stay malicious essentially forever, so they
# decay slowly and CVEs slower still.
DECAY_HALF_LIFE_HOURS: Dict[str, float] = {
    "url": 24 * 7.0,
    "ipv4": 24 * 7.0,
    "ipv6": 24 * 7.0,
    "domain": 24 * 14.0,
    "ipv4_cidr": 24 * 30.0,
    "ipv6_cidr": 24 * 30.0,
    "ja3": 24 * 30.0,
    "ja3s": 24 * 30.0,
    "email": 24 * 30.0,
    "btc_address": 24 * 90.0,
    "md5": 24 * 180.0,
    "sha1": 24 * 180.0,
    "sha256": 24 * 180.0,
    "sha512": 24 * 180.0,
    "cve": 24 * 365.0,
}
DEFAULT_HALF_LIFE_HOURS = 24 * 14.0


def compute_score(indicator: Indicator, now: Optional[datetime] = None) -> int:
    """Score an indicator 0-100: confidence base + corroboration, decayed by age.

    Decay is exponential on hours since ``last_seen`` with a per-type
    half-life, so a freshly observed indicator keeps its full score and a
    stale one fades until it drops below the expiry threshold.
    """
    now = now or now_utc()
    base = SCORE_BASE.get(indicator.confidence, 50)
    n_sources = len([s for s in indicator.source.split(",") if s.strip()])
    bonus = min(max(n_sources - 1, 0) * CORROBORATION_BONUS, CORROBORATION_CAP)
    last = parse_dt(indicator.last_seen) or now
    age_hours = max((now - last).total_seconds() / 3600.0, 0.0)
    half_life = DECAY_HALF_LIFE_HOURS.get(indicator.type, DEFAULT_HALF_LIFE_HOURS)
    decay = 0.5 ** (age_hours / half_life)
    return max(0, min(100, round((base + bonus) * decay)))


def source_count(indicator: Indicator) -> int:
    """Number of independent feeds reporting this indicator."""
    return len([s for s in indicator.source.split(",") if s.strip()])


def high_confidence_rows(rows: List[Indicator], *, min_score: int = 80) -> List[Indicator]:
    """Curated subset safe to action directly.

    An indicator qualifies if it scores at or above ``min_score`` (fresh +
    confident) OR is corroborated by two or more independent sources. This is
    the "block-ready" feed: high-signal, low-false-positive.
    """
    return [r for r in rows if r.score >= min_score or source_count(r) >= 2]


def load_previous_feed(path: Path) -> List[Indicator]:
    """Load a previously published latest.jsonl so the feed can persist.

    Tolerant of missing files, malformed lines, and schema drift (unknown
    keys are ignored; rows missing required fields are skipped). Entries that
    the current false-positive rules would reject are dropped on load, so an
    improved FP list retroactively cleans the carried-forward feed.
    """
    if not path.exists():
        return []
    field_names = {f.name for f in dataclass_fields(Indicator)}
    out: List[Indicator] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        try:
            ind = Indicator(**{k: v for k, v in data.items() if k in field_names})
        except TypeError:
            continue
        if is_false_positive(ind.type, ind.indicator):
            continue
        out.append(ind)
    return out


def merge_with_previous(current: List[Indicator], previous: List[Indicator]) -> Tuple[List[Indicator], int]:
    """Merge the previous feed into this run's results ("living feed").

    Indicators re-observed this run keep their fresh ``last_seen`` (so their
    score resets to full) while inheriting the earliest ``first_seen`` and the
    accumulated source/tag history. Indicators seen only previously are
    carried forward untouched — their stale ``last_seen`` makes the decay
    scoring fade them out until expiry. Returns (merged, carried_forward).
    """
    uniq: Dict[Tuple[str, str], Indicator] = {i.key(): i for i in current}
    carried = 0
    for prev in previous:
        k = prev.key()
        if k not in uniq:
            uniq[k] = prev
            carried += 1
            continue
        cur = uniq[k]
        p_first = parse_dt(prev.first_seen)
        c_first = parse_dt(cur.first_seen)
        if p_first and (c_first is None or p_first < c_first):
            cur.first_seen = prev.first_seen
        merged_tags = set(filter(None, cur.tags.split(","))) | set(filter(None, prev.tags.split(",")))
        cur.tags = ",".join(sorted(t for t in merged_tags if t))
        merged_sources = set(filter(None, cur.source.split(","))) | set(filter(None, prev.source.split(",")))
        cur.source = ",".join(sorted(merged_sources))
        cur.confidence = merge_conf(cur.confidence, prev.confidence)
    merged = sorted(uniq.values(), key=lambda r: (r.type, r.indicator, r.source))
    return merged, carried


# ---------------- false-positive / bogon filtering ----------------
# Values that are never actionable threat indicators and only add noise to a
# feed. Bogon IP ranges (private, loopback, link-local, reserved, ...) are
# detected structurally via the ipaddress module.
FP_DOMAINS: Set[str] = {
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "localhost.localdomain", "test", "invalid", "local",
}
FP_DOMAIN_SUFFIXES: Tuple[str, ...] = (
    ".example.com", ".example.org", ".example.net",
    ".arpa", ".localhost", ".local", ".test", ".invalid",
)
FP_IPS: Set[str] = {"0.0.0.0", "255.255.255.255", "::", "::1"}


def _ip_is_bogon(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def _net_is_bogon(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return bool(
        net.is_private or net.is_loopback or net.is_link_local
        or net.is_multicast or net.is_reserved or net.is_unspecified
    )


def _domain_is_fp(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in FP_DOMAINS:
        return True
    return any(host.endswith(suffix) for suffix in FP_DOMAIN_SUFFIXES)


def is_false_positive(itype: str, value: str) -> bool:
    """Return True for well-known benign values that should not enter the feed."""
    raw = refang(value)
    if itype in {"ipv4", "ipv6"}:
        return raw in FP_IPS or _ip_is_bogon(raw)
    if itype in {"ipv4_cidr", "ipv6_cidr"}:
        return _net_is_bogon(raw)
    if itype == "domain":
        return _domain_is_fp(raw)
    if itype == "url":
        m = _URL_HEAD_RE.match(raw)
        if m:
            host = m.group(3).split("@")[-1].split(":")[0]
            return host in FP_IPS or _ip_is_bogon(host) or _domain_is_fp(host)
    return False


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
    for cve in set(CVE_RE.findall(blob)):
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
    adapter = HTTPAdapter(
        max_retries=Retry(
            # A single flaky/rate-limiting source (public threat feeds and
            # shared CI-runner IP ranges do not mix well) must not be able to
            # stall the whole run for minutes: worst case here is ~4 attempts
            # * 20s timeout + ~3.5s of backoff sleep (~85s), versus the
            # previous 6 attempts * 30s + ~31s backoff (~211s) per source.
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504, 520, 521, 522, 523, 524),
            allowed_methods=frozenset({"GET", "HEAD"}),
            raise_on_status=False,
        )
    )
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


def http_get(url: str, *, name: str, kind: str = "text", timeout: int = 20) -> str | bytes:
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
            continue

        first_seen = parse_dt(row[0]) if row[0] else None
        if not disable_window and first_seen and first_seen < ws:
            continue

        desc = row[2] if len(row) > 2 else ""

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
    max_workers: int = 8,
    fp_filter: bool = True,
) -> Tuple[List[Indicator], Dict[str, int], Dict[str, Any]]:
    base_start = now_utc() - timedelta(hours=window_hours)

    def start_for(name: str) -> datetime:
        if name in source_window:
            return now_utc() - timedelta(hours=source_window[name])
        return base_start

    def cap(xs: List[Indicator]) -> List[Indicator]:
        return xs[:max_per_source] if (max_per_source and len(xs) > max_per_source) else xs

    # Each source is fetched by a worker returning a result dict so the network
    # I/O can be run concurrently. Workers never raise: failures are captured in
    # the result so one bad feed cannot abort the whole run.
    def run_api(api: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = api.get("name", "api")
        parse = api.get("parse")
        if not parse:
            return None
        url = api.get("url", "")
        ref = api.get("reference", url) or ""
        ws = start_for(name)
        got: List[Indicator] = []
        options: Dict[str, Any] = {}
        failure: Optional[Dict[str, str]] = None
        try:
            t0 = time.perf_counter()
            parser_fn = resolve_parser(parse)
            parser_sig = inspect.signature(parser_fn)
            supported_kwargs = {
                k
                for k in parser_sig.parameters
                if k not in {"url", "ref_url", "source", "ws"}
            }

            options = dict(api.get("options", {}))
            for key in (
                "fallback_url",
                "graceful_404",
                "status_filter",
                "disable_window",
                "graceful_fail",
            ):
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
            graceful_fail = bool(api.get("graceful_fail") or options.get("graceful_fail"))
            logger.warning("%s failed: %s", name, e)
            if not graceful_fail:
                failure = {"source": name, "error": str(e)}
            got = []
        return {"name": name, "indicators": got, "failure": failure}

    def run_rss(rss: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        name = rss.get("name", "rss")
        url = rss.get("url")
        if not url:
            return None
        ref = rss.get("reference", url) or ""
        got: List[Indicator] = []
        failure: Optional[Dict[str, str]] = None
        try:
            t0 = time.perf_counter()
            got = fetch_rss(url, ref, name, start_for(name), tolerate_missing=ci_safe_rss)
            dt = time.perf_counter() - t0
            logger.debug("collect RSS %s %d in %.2fs", name, len(got), dt)
            logger.debug("summary %s types=%s tags_top=%s", name, type_counts(got), top_tags(got))
        except Exception as e:
            graceful_fail = bool(rss.get("graceful_fail"))
            logger.warning("%s failed: %s", name, e)
            if not graceful_fail:
                failure = {"source": name, "error": str(e)}
            got = []
        return {"name": name, "indicators": got, "failure": failure}

    # Build the ordered task list (APIs first, then RSS) so results stay
    # deterministic regardless of which worker finishes first.
    tasks: List[Tuple[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]], Dict[str, Any]]] = []
    for api in cfg.get("apis", []) or []:
        tasks.append((run_api, api))
    if not skip_rss:
        for rss in cfg.get("rss", []) or []:
            tasks.append((run_rss, rss))

    # Pre-initialise the shared HTTP session before fanning out so the workers
    # don't race on lazy creation.
    ensure_session()

    results: List[Optional[Dict[str, Any]]] = [None] * len(tasks)
    workers = max(1, min(max_workers, len(tasks))) if tasks else 1
    if workers > 1:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(fn, item): idx for idx, (fn, item) in enumerate(tasks)}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
    else:
        for idx, (fn, item) in enumerate(tasks):
            results[idx] = fn(item)

    indicators: List[Indicator] = []
    counts: Dict[str, int] = {}
    failures: List[Dict[str, str]] = []
    raw_total = 0
    fp_removed = 0
    for result in results:
        if result is None:
            continue
        if result["failure"]:
            failures.append(result["failure"])
        # Canonicalise host casing and drop bogon / benign false positives
        # *before* applying --max-per-source, so a cap doesn't get filled with
        # early junk rows while later, legitimate indicators are truncated away.
        kept: List[Indicator] = []
        for ind in result["indicators"]:
            ind.indicator = normalize_value(ind.type, ind.indicator)
            if fp_filter and is_false_positive(ind.type, ind.indicator):
                fp_removed += 1
                continue
            kept.append(ind)
        got = cap(kept)
        raw_total += len(got)
        indicators.extend(got)
        counts[result["name"]] = len(got)

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
        "false_positives_removed": fp_removed,
    }
    return final, counts, stats


# ---------------- writers ----------------
CSV_HEADER = ["indicator", "type", "source", "first_seen", "last_seen", "confidence", "score", "tlp", "tags", "reference", "context"]


def _csv_row(r: Indicator) -> List[Any]:
    return [r.indicator, r.type, r.source, r.first_seen, r.last_seen, r.confidence, r.score, r.tlp, r.tags, r.reference, r.context]


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
    ap.add_argument("--max-workers", type=int, default=8, help="Concurrent source fetches (1 disables threading)")
    ap.add_argument("--no-fp-filter", dest="fp_filter", action="store_false", help="Disable bogon / false-positive filtering")
    ap.set_defaults(fp_filter=True)
    ap.add_argument("--persist-feed", action="store_true",
                    help="Living feed: merge the previously published latest.jsonl, decay scores by age, expire stale entries")
    ap.add_argument("--min-score", type=int, default=20,
                    help="Expire indicators whose decayed score falls below this (default 20)")
    ap.add_argument("--high-confidence-score", type=int, default=80,
                    help="Score at/above which an indicator enters the curated high_confidence feed (default 80)")
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
    # Default to None so unset paths can follow --out-dir instead of always
    # landing in ./public (which silently wrote into the repo when running
    # with a custom --out-dir).
    ap.add_argument("--diag-json", type=Path, default=None, help="Diagnostics JSON path (default: <out-dir>/diagnostics/run.json)")
    ap.add_argument("--report", type=Path, default=None, help="Markdown run report path (default: <out-dir>/diagnostics/REPORT.md)")
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
        # RSS still runs; fetch_rss tolerates a missing feedparser dependency.
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

    # Derive unset diagnostics paths from --out-dir, then ensure the dirs
    # exist (nice for GH Artifacts).
    if args.diag_json is None:
        args.diag_json = args.out_dir / "diagnostics" / "run.json"
    if args.report is None:
        args.report = args.out_dir / "diagnostics" / "REPORT.md"
    args.diag_json.parent.mkdir(parents=True, exist_ok=True)
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
        max_workers=args.max_workers,
        fp_filter=args.fp_filter,
    )

    out_dir: Path = args.out_dir

    # Living feed: merge the previously published feed so indicators persist
    # across runs. Re-observed entries refresh (score resets to full); entries
    # no longer being reported decay by age until they expire below --min-score.
    carried_forward = 0
    if args.persist_feed:
        previous = load_previous_feed(out_dir / "iocs" / "latest.jsonl")
        rows, carried_forward = merge_with_previous(rows, previous)
        logger.info("Persisted feed: carried forward %d indicators from previous run", carried_forward)

    score_now = now_utc()
    for r in rows:
        r.score = compute_score(r, score_now)
    before_expiry = len(rows)
    rows = [r for r in rows if r.score >= args.min_score]
    expired = before_expiry - len(rows)
    if expired:
        logger.info("Expired %d indicators below score threshold %d", expired, args.min_score)

    # outputs
    write_csv(out_dir / "iocs" / "latest.csv", rows)
    write_tsv(out_dir / "iocs" / "latest.tsv", rows)
    write_json(out_dir / "iocs" / "latest.json", rows)
    write_jsonl(out_dir / "iocs" / "latest.jsonl", rows)
    write_stix(out_dir / "iocs" / "stix2.json", rows)

    # Curated "block-ready" feed: only high-score or multi-source-confirmed
    # indicators, sorted strongest-first so the top of the file is the most
    # dangerous. Compact, so it is committed to git for direct raw-URL use.
    high_conf = sorted(
        high_confidence_rows(rows, min_score=args.high_confidence_score),
        key=lambda r: (-r.score, -source_count(r), r.type, r.indicator),
    )
    write_csv(out_dir / "iocs" / "high_confidence.csv", high_conf)
    write_jsonl(out_dir / "iocs" / "high_confidence.jsonl", high_conf)
    logger.info(
        "High-confidence feed: %d of %d indicators (score>=%d or 2+ sources)",
        len(high_conf), len(rows), args.high_confidence_score,
    )

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
    scores = [r.score for r in rows]
    diag = {
        "window_hours": args.window_hours,
        "total": len(rows),
        "total_before_dedup": raw_total,
        "duplicates_removed": duplicates_removed,
        "false_positives_removed": stats.get("false_positives_removed", 0),
        "persist_feed": bool(args.persist_feed),
        "carried_forward": carried_forward,
        "expired_low_score": expired,
        "score_min": min(scores) if scores else None,
        "score_avg": round(sum(scores) / len(scores), 1) if scores else None,
        "score_max": max(scores) if scores else None,
        "high_confidence_total": len(high_conf),
        "high_confidence_score": args.high_confidence_score,
        "counts": counts,
        "type_counts": {k: v for k, v in type_totals},
        "earliest_first_seen": earliest,
        "newest_first_seen": latest,
        "empty_sources": empty_sources,
        "failures": stats.get("failures", []),
        "version": 3,
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
        if args.persist_feed:
            report_lines.append(f"| Carried forward | {carried_forward} |")
            report_lines.append(f"| Expired (score < {args.min_score}) | {expired} |")
        if scores:
            report_lines.append(f"| Score (min / avg / max) | {min(scores)} / {round(sum(scores) / len(scores), 1)} / {max(scores)} |")
        report_lines.append(f"| High-confidence indicators | {len(high_conf)} |")
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
