"""SwiftIOC: automated threat-intel collector — package public API.

Everything the CLI, tests, and downstream consumers use is re-exported here,
so ``import swiftioc as si; si.classify(...)`` keeps working exactly as it
did when this was a single ``swiftioc.py`` script.

Import order matters: submodules are imported bottom-up (``models`` first,
``cli`` last) matching their dependency chain. ``parsers.py`` does
``import swiftioc as _pkg`` at its own top — a *circular* self-import. That
is safe here because Python registers a package in ``sys.modules`` before
running its ``__init__.py`` body, so by the time ``parsers`` reaches that
line, ``swiftioc`` already exists as a (partially built) module object;
``_pkg`` only gets dereferenced *inside function bodies*, which never run
until this file has finished executing. See ``parsers.py`` for why that
indirection exists (test monkeypatching of ``http_get``/``load_feedparser``).
"""
from __future__ import annotations

from . import http_client  # noqa: F401  (submodule access, e.g. swiftioc.http_client)
from .models import (
    BTC_INLINE_RE,
    BTC_RE,
    CONF_RANK,
    CVE_RE,
    DATE_FIELD_RE,
    DOMAIN_RE,
    EMAIL_RE,
    ISO_FMT,
    JA3_RE,
    MD5_RE,
    SHA1_RE,
    SHA256_RE,
    SHA512_RE,
    TAGS_FIELD_RE,
    URL_SCHEME_RE,
    Indicator,
    classify,
    defang_min,
    iso,
    merge_conf,
    normalize_value,
    now_utc,
    parse_dt,
    refang,
)
from .fp import (
    FP_DOMAIN_SUFFIXES,
    FP_DOMAINS,
    FP_IPS,
    is_false_positive,
)
from .extract import extract_indicators_from_text
from .http_client import (
    DEFAULT_UAS,
    UA_POOL,
    build_session,
    choose_ua,
    ensure_session,
    ensure_text,
    get_fetch_metrics,
    http_get,
    load_feedparser,
    reset_fetch_metrics,
    save_raw,
)
from .scoring import (
    CORROBORATION_BONUS,
    CORROBORATION_CAP,
    DECAY_HALF_LIFE_HOURS,
    DEFAULT_HALF_LIFE_HOURS,
    SCORE_BASE,
    apply_retention,
    compute_score,
    high_confidence_rows,
    load_previous_feed,
    merge_with_previous,
    source_count,
)
from .parsers import (
    PARSERS,
    ParserRegistry,
    fetch_blocklist_txt,
    fetch_cins_army,
    fetch_cisa_kev,
    fetch_dshield_block,
    fetch_feodo_ipblocklist,
    fetch_malwarebazaar_csv,
    fetch_nvd_recent,
    fetch_openphish,
    fetch_rss,
    fetch_spamhaus_drop,
    fetch_sslbl_ja3,
    fetch_sslbl_ja3s,
    fetch_threatfox_export_json,
    fetch_tor_exit,
    fetch_universal,
    fetch_urlhaus_csv,
    register_parser,
    resolve_parser,
)
from .collect import (
    collect_from_yaml,
    parse_name_int_pairs,
    top_tags,
    type_breakdown,
    type_counts,
)
from .writers import (
    CSV_HEADER,
    MISP_ATTRIBUTE_TYPES,
    MISP_CATEGORY_BY_TYPE,
    STIX_HASH_NAMES,
    STIX_IDENTITY_ID,
    STIX_NAMESPACE,
    STIX_TLP_ID,
    write_badge_json,
    write_changelog,
    write_csv,
    write_dashboard_feed,
    write_history,
    write_json,
    write_jsonl,
    write_misp_feed,
    write_rss_feed,
    write_stix,
    write_tsv,
)
from .logging_utils import JsonLineFormatter, configure_logging
from .cli import gh_summary_path, append_gh_summary, main

__version__ = "0.3.0"

__all__ = [
    "__version__",
    # models
    "Indicator", "classify", "defang_min", "refang", "normalize_value",
    "merge_conf", "now_utc", "iso", "parse_dt", "ISO_FMT", "CONF_RANK",
    "JA3_RE", "SHA512_RE", "EMAIL_RE", "BTC_RE", "BTC_INLINE_RE",
    "DATE_FIELD_RE", "TAGS_FIELD_RE", "URL_SCHEME_RE", "DOMAIN_RE",
    "MD5_RE", "SHA1_RE", "SHA256_RE", "CVE_RE",
    # false positives
    "is_false_positive", "FP_DOMAINS", "FP_DOMAIN_SUFFIXES", "FP_IPS",
    # extraction
    "extract_indicators_from_text",
    # http
    "http_get", "ensure_text", "ensure_session", "build_session",
    "choose_ua", "save_raw", "load_feedparser", "UA_POOL", "DEFAULT_UAS",
    "reset_fetch_metrics", "get_fetch_metrics",
    # scoring
    "compute_score", "source_count", "high_confidence_rows",
    "apply_retention", "load_previous_feed", "merge_with_previous",
    "SCORE_BASE", "CORROBORATION_BONUS", "CORROBORATION_CAP",
    "DECAY_HALF_LIFE_HOURS", "DEFAULT_HALF_LIFE_HOURS",
    # parsers
    "PARSERS", "ParserRegistry", "register_parser", "resolve_parser",
    "fetch_cisa_kev", "fetch_nvd_recent", "fetch_urlhaus_csv", "fetch_dshield_block",
    "fetch_malwarebazaar_csv", "fetch_threatfox_export_json",
    "fetch_feodo_ipblocklist", "fetch_sslbl_ja3", "fetch_sslbl_ja3s",
    "fetch_spamhaus_drop", "fetch_openphish", "fetch_cins_army",
    "fetch_tor_exit", "fetch_blocklist_txt", "fetch_rss", "fetch_universal",
    # collect
    "collect_from_yaml", "parse_name_int_pairs", "type_counts",
    "type_breakdown", "top_tags",
    # writers
    "write_csv", "write_tsv", "write_json", "write_jsonl", "write_stix",
    "write_misp_feed", "write_rss_feed", "write_badge_json", "write_history",
    "write_changelog", "write_dashboard_feed", "CSV_HEADER",
    "STIX_NAMESPACE", "STIX_IDENTITY_ID", "STIX_TLP_ID", "STIX_HASH_NAMES",
    "MISP_ATTRIBUTE_TYPES", "MISP_CATEGORY_BY_TYPE",
    # logging
    "JsonLineFormatter", "configure_logging",
    "gh_summary_path", "append_gh_summary",
    # cli
    "main",
]
