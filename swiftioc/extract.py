"""Free-text indicator extraction (used by RSS/universal parsers)."""
from __future__ import annotations

import logging
from collections.abc import Iterable as IterableABC
from typing import Any, Callable, Iterable, List, Optional, Tuple, cast

import iocextract

from .models import BTC_INLINE_RE, CVE_RE, JA3_RE, classify

logger = logging.getLogger("swiftioc")


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

