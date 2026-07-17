"""Shared HTTP session, user-agent pool, and lazy feedparser loader.

``cli.py`` mutates ``_SAVE_RAW_DIR`` / ``HTTP_DEBUG`` on *this* module object
(``http_client._SAVE_RAW_DIR = ...``) rather than importing and rebinding
those names locally — a local rebind would only affect cli.py's own
namespace, not the globals ``http_get``/``save_raw`` actually read here.
"""
from __future__ import annotations

import logging
import random
import time
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("swiftioc")

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
_SESSION: Optional[requests.Session] = None
_FEEDPARSER = None
_SAVE_RAW_DIR: Optional[Path] = None
HTTP_DEBUG = False
# Per-fetch telemetry ({name: {ms, bytes, status}}) filled by http_get, drained
# into diagnostics so the dashboard can show a feed-health / latency panel.
_FETCH_METRICS: Dict[str, Dict[str, Any]] = {}


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
    # Record telemetry before raise_for_status so failed statuses are captured.
    _FETCH_METRICS[name] = {
        "ms": round(dt * 1000),
        "bytes": len(r.content),
        "status": r.status_code,
    }
    if HTTP_DEBUG:
        logger.debug("HTTP %s %.2fs %s [%s]", r.status_code, dt, url, name)
    r.raise_for_status()
    body = r.text if kind == "text" else r.content
    save_raw(name, body, kind)
    return body


def reset_fetch_metrics() -> None:
    _FETCH_METRICS.clear()


def get_fetch_metrics() -> Dict[str, Dict[str, Any]]:
    return dict(_FETCH_METRICS)


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

