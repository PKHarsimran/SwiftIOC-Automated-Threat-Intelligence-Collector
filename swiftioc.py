#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import ipaddress
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
from typing import Any, Dict, List, Optional, Set, Tuple

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


def classify(v: str) -> Optional[str]:
    s = v.strip()
    try:
        ipaddress.ip_address(s)
        return "ipv6" if ":" in s else "ipv4"
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
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", s, re.IGNORECASE):
        return "cve"
    return None


def merge_conf(a: str, b: str) -> str:
    return a if CONF_RANK.get(a, 0) >= CONF_RANK.get(b, 0) else b


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
        with (p.open("w", encoding="utf-8") if kind == "text" else p.open("wb")) as f:
            f.write(content)
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


def fetch_urlhaus_csv(url: str, ref_url: str, source: str, ws: datetime, *, status_filter: str = "any") -> List[Indicator]:
    text = http_get(url, name=source)
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


def fetch_malwarebazaar_csv(url: str, ref_url: str, source: str, ws: datetime, *, fallback_url: Optional[str] = None, graceful_404: bool = False) -> List[Indicator]:
    try:
        text = http_get(url, name=source)
    except requests.HTTPError as e:
        if getattr(e, "response", None) and e.response.status_code == 404 and fallback_url:
            logger.warning("%s 404, falling back to %s", url, fallback_url)
            text = http_get(fallback_url, name=f"{source}_fallback")
        elif getattr(e, "response", None) and e.response.status_code == 404 and graceful_404:
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
            first_seen = parse_dt(row[0]); sha256 = row[4]; sig = row[7] if len(row) > 7 else ""
        except Exception:
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


def fetch_threatfox_export_json(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = http_get(url, name=source)
    data = json.loads(text)
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


def fetch_feodo_ipblocklist(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = http_get(url, name=source)
    out: List[Indicator] = []
    now = now_utc()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):
            continue
        try:
            seen = parse_dt(row[0]); ip = row[1]; family = row[5] if len(row) > 5 else ""
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


def fetch_sslbl_ja3(url: str, ref_url: str, source: str, ws: datetime, *, kind: str = "ja3") -> List[Indicator]:
    text = http_get(url, name=source)
    out: List[Indicator] = []
    now = now_utc()
    for row in csv.reader(io.StringIO(text)):
        if not row or row[0].startswith("#"):
            continue
        ja = row[1] if len(row) > 1 else None
        if not ja:
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


def fetch_spamhaus_drop(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = http_get(url, name=source)
    out: List[Indicator] = []
    now = now_utc()
    if isinstance(text, str):
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


def fetch_openphish(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = http_get(url, name=source)
    out: List[Indicator] = []
    now = now_utc()
    if isinstance(text, str):
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


def fetch_cins_army(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = http_get(url, name=source)
    out: List[Indicator] = []
    now = now_utc()
    if isinstance(text, str):
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


def fetch_tor_exit(url: str, ref_url: str, source: str, ws: datetime) -> List[Indicator]:
    text = http_get(url, name=source)
    out: List[Indicator] = []
    now = now_utc()
    if isinstance(text, str):
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
            if getattr(e, k, None):
                published = parse_dt(getattr(e, k)); break
        if not published:
            published = feed_updated
        if published and published < ws:
            continue
        text_parts = [getattr(e, "title", ""), getattr(e, "summary", "")]
        for c in getattr(e, "content", []) or []:
            text_parts.append(c.get("value", ""))
        blob = "\n".join(filter(None, text_parts))
        found: List[Tuple[str, str]] = []
        for u in iocextract.extract_urls(blob, refang=False): found.append(("url", u))
        for ip in iocextract.extract_ips(blob): found.append(("ipv4", ip))
        for d in iocextract.extract_domains(blob): found.append(("domain", d))
        for h in iocextract.extract_hashes(blob): found.append((classify(h) or "sha256", h))
        for cve in set(re.findall(r"CVE-\d{4}-\d{4,7}", blob, flags=re.I)): found.append(("cve", cve.upper()))
        if not found:
            continue
        seen: Set[Tuple[str, str]] = set()
        count = 0
        ref = getattr(e, "link", None) or ref_url or url
        for t, val in found:
            if count >= per_entry_cap: break
            k = (t, val)
            if k in seen: continue
            seen.add(k); count += 1
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
    wanted = ("url", "domain", "ipv4", "sha256", "cve", "ipv4_cidr", "ja3", "ja3s")
    return {t: sum(1 for r in items if r.type == t) for t in wanted}


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
) -> Tuple[List[Indicator], Dict[str, int]]:
    base_start = now_utc() - timedelta(hours=window_hours)

    def start_for(name: str) -> datetime:
        if name in source_window:
            return now_utc() - timedelta(hours=source_window[name])
        return base_start

    def cap(xs: List[Indicator]) -> List[Indicator]:
        return xs[:max_per_source] if (max_per_source and len(xs) > max_per_source) else xs

    indicators: List[Indicator] = []
    counts: Dict[str, int] = {}

    # APIs
    for api in cfg.get("apis", []) or []:
        name = api.get("name", "api")
        parse = api.get("parse")
        if not parse:
            continue
        url = api.get("url", "")
        ref = api.get("reference", url) or ""
        fb = api.get("fallback_url")
        ws = start_for(name)
        got: List[Indicator] = []
        try:
            t0 = time.perf_counter()
            if parse == "kev":
                got = fetch_cisa_kev(url, ref, name, ws)
            elif parse == "urlhaus":
                got = fetch_urlhaus_csv(url, ref, name, ws, status_filter=urlhaus_status)
            elif parse == "malwarebazaar":
                got = fetch_malwarebazaar_csv(url, ref, name, ws, fallback_url=fb, graceful_404=(name in grace_on_404))
            elif parse == "threatfox_export_json":
                got = fetch_threatfox_export_json(url, ref, name, ws)
            elif parse == "feodo_ipblocklist":
                got = fetch_feodo_ipblocklist(url, ref, name, ws)
            elif parse == "sslbl_ja3":
                got = fetch_sslbl_ja3(url, ref, name, ws, kind="ja3")
            elif parse == "sslbl_ja3s":
                got = fetch_sslbl_ja3(url, ref, name, ws, kind="ja3s")
            elif parse == "spamhaus_drop":
                got = fetch_spamhaus_drop(url, ref, name, ws)
            elif parse == "openphish":
                got = fetch_openphish(url, ref, name, ws)
            elif parse == "cins_army":
                got = fetch_cins_army(url, ref, name, ws)
            elif parse == "tor_exit":
                got = fetch_tor_exit(url, ref, name, ws)
            dt = time.perf_counter() - t0
            logger.debug("collect %s %d in %.2fs", name, len(got), dt)
            logger.debug("summary %s types=%s tags_top=%s", name, type_counts(got), top_tags(got))
        except Exception as e:
            logger.warning("%s failed: %s", name, e)
            got = []
        got = cap(got)
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
                got = []
            got = cap(got)
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
    return final, counts


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
        logger.warning("UA file not found: %s", path); return
    try:
        pool = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
        if pool:
            UA_POOL.clear(); UA_POOL.extend(pool)
            logger.info("Loaded %d User-Agents from %s", len(pool), path)
    except Exception as e:
        logger.warning("Failed loading UA file: %s", e)


# ---------------- small helpers ----------------
def gh_summary_path() -> Optional[Path]:
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    return Path(p) if p else None


def append_gh_summary(lines: List[str]) -> None:
    p = gh_summary_path()
    if not p: return
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
    if args.verbose == 1: console_level = logging.INFO
    elif args.verbose >= 2: console_level = logging.DEBUG
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
    rows, counts = collect_from_yaml(
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
    diag = {
        "window_hours": args.window_hours,
        "total": len(rows),
        "counts": counts,
        "version": 1,
        "ts": iso(now_utc()),
    }
    if args.diag_json:
        args.diag_json.write_text(json.dumps(diag, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.report:
        args.report.write_text(
            "\n".join(
                [
                    "# SwiftIOC Run Report",
                    "",
                    f"**Started:** {iso(now_utc())}",
                    f"**Window (hours):** {args.window_hours}",
                    f"**Total indicators:** {len(rows)}",
                    "",
                    "## Per-source counts",
                    *[f"- {k}: {v}" for k, v in sorted(counts.items())],
                    "",
                ]
            ),
            encoding="utf-8",
        )

    # Append a brief GH step summary (if available)
    append_gh_summary(
        [
            "### SwiftIOC",
            f"- Total indicators: **{len(rows)}**",
            "- Per-source counts:",
            *[f"  - {k}: {v}" for k, v in sorted(counts.items())],
            "",
        ]
    )

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
