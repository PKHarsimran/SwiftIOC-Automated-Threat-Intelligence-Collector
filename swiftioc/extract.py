"""Free-text indicator extraction (used by RSS/universal parsers)."""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable as IterableABC
from typing import Any, Callable, Iterable, List, Optional, Tuple, cast

import iocextract

from .models import BTC_INLINE_RE, CVE_RE, JA3_RE, classify

logger = logging.getLogger("swiftioc")


# ---------------- indicator extraction helpers ----------------
def _safe_iocextract(name: str, *args: Any, **kwargs: Any) -> Iterable[str]:
    func = getattr(iocextract, name, None)
    if not callable(func):
        logger.warning(
            "iocextract has no attribute %r (dependency API drift?) — that extraction category is silently skipped", name
        )
        return []
    try:
        result = func(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("iocextract %s failed: %s", name, exc)
        return []
    if isinstance(result, str) or not isinstance(result, IterableABC):
        return []
    return cast(Iterable[str], result)


_BARE_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,24}\b")

# Common file extensions that are syntactically indistinguishable from a
# single-label TLD (e.g. "readme.md", "payload.exe") — excluded so free-text
# extraction doesn't mislabel filenames mentioned in threat write-ups as
# domains. Not exhaustive; classify()/is_false_positive() catch the rest.
_LIKELY_FILE_EXT = {
    "exe", "dll", "bin", "dat", "bak", "zip", "rar", "7z", "gz", "tar",
    "txt", "log", "csv", "json", "yaml", "yml", "cfg", "ini", "ps1", "sh",
    "py", "js", "md", "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg",
    "jpeg", "gif", "svg",
}


def _extract_bare_domains(blob: str) -> Iterable[str]:
    """Find bare-domain mentions that iocextract has no function for.

    iocextract (1.16.x) exposes extract_urls/ips/hashes/emails but no
    extract_domains — threat write-ups routinely mention a C2/phishing
    domain without an http(s):// prefix, which iocextract simply cannot
    recover. Candidate tokens are validated with classify() at the call
    site, so a domain-shaped-but-wrong match (or something classify()
    recognizes as an IP) is not blindly trusted.
    """
    seen = set()
    for m in _BARE_DOMAIN_RE.finditer(blob):
        token = m.group(0).rstrip(".")
        tld = token.rsplit(".", 1)[-1].lower()
        if tld in _LIKELY_FILE_EXT or token in seen:
            continue
        seen.add(token)
        yield token


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
    for domain in _extract_bare_domains(blob):
        if classify(domain) == "domain":
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

