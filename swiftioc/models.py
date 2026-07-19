"""Core data model, timestamp helpers, defang/normalize, and classification.

No other ``swiftioc`` submodule is imported here — this is the dependency
floor everything else (scoring, parsers, writers, collect, cli) builds on.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

from dateutil import parser as dtparser

ISO_FMT = "%Y-%m-%dT%H:%M:%SZ"
CONF_RANK = {"low": 10, "medium": 50, "high": 90}


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
    # How many collection runs have re-observed this indicator (persisted
    # across runs via the living feed). 1 = seen in this run only.
    sightings: int = 1

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
        dt: datetime = dtparser.parse(s)  # explicit annotation: dateutil's stub return type is unreliable here
    except Exception:
        return None
    # A naive result (no tzinfo) means the source string had no offset/Z
    # marker — several feeds (URLhaus, MalwareBazaar, Feodo, SSLBL) emit
    # exactly this despite "_utc"-suffixed field names. .astimezone() on a
    # naive datetime assumes the HOST machine's local timezone, silently
    # corrupting first_seen/last_seen (and everything downstream: scoring
    # decay, retention windows) on any non-UTC machine. Treat naive input as
    # already UTC instead.
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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


def _split_authority(authority: str) -> Tuple[str, str, str]:
    """Split a URL authority into (userinfo_with_at, host, port).

    ``authority`` is ``[userinfo@]host[:port]``. An IPv6 literal host is
    RFC 3986 ``[...]``-bracketed so its own colons aren't mistaken for the
    port separator (a naive ``split(":")[0]`` yields garbage like ``"["`` for
    ``"[::1]:8080"``). ``host`` is returned WITHOUT brackets, so callers can
    hand it straight to ``ipaddress.ip_address()`` or domain matching;
    ``userinfo_with_at`` includes the trailing ``@`` (or is ``""``).
    """
    userinfo, at, hostport = authority.rpartition("@") if "@" in authority else ("", "", authority)
    if hostport.startswith("["):
        end = hostport.find("]")
        if end != -1:
            host = hostport[1:end]
            rest = hostport[end + 1 :]
            port = rest[1:] if rest.startswith(":") else ""
            return userinfo + at, host, port
        return userinfo + at, hostport, ""
    host, _sep, port = hostport.partition(":")
    return userinfo + at, host, port


def _lower_authority_host(authority: str) -> str:
    """Lowercase only the host portion of a URL authority component.

    Userinfo (which may carry a case-sensitive username/password/token) is
    preserved verbatim; only the host — re-bracketed if it's IPv6 — and its
    brackets are lowercased.
    """
    userinfo_at, host, port = _split_authority(authority)
    lowered = host.lower()
    if ":" in lowered:  # IPv6 literal — re-wrap in brackets
        lowered = f"[{lowered}]"
    return userinfo_at + lowered + (f":{port}" if port else "")


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

