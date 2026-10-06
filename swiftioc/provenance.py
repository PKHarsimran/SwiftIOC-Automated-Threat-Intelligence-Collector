"""Conservative publisher grouping for scoring shipped feed adapters.

An adapter name is not an independent observer. Unknown custom names retain
their own identities until an operator maps their publisher; that is a
counting convention, not a claim of independent verification.
"""
from __future__ import annotations

from typing import Any

_REPORTING = {
    "cisa": ("cisa_kev",),
    "nvd": ("nist_nvd_recent",),
    "abuse.ch": ("threatfox_export_json", "threatfox_recent", "threatfox", "urlhaus_recent_urls", "urlhaus",
                 "malwarebazaar_recent", "malwarebazaar", "feodo_ipblocklist", "feodo", "sslbl_ja3", "sslbl"),
    "cins": ("ci_army_list", "cins"),
    "spamhaus": ("spamhaus_drop", "spamhaus_drop_v6", "spamhaus"),
    "dshield": ("dshield_block", "dshield", "sans-isc"),
    "blocklist.de": ("blocklist_de_ssh", "blocklist_de_all"),
    "greensnow": ("greensnow_blocklist", "greensnow"),
    "openphish": ("openphish_feed", "openphish"),
    "emerging-threats": ("et_compromised", "emerging-threats"),
    "binarydefense": ("binarydefense_banlist", "binarydefense"),
}
_NONREPORTING = {
    "aggregate": {"ipsum_level5", "ipsum"},
    "context": {"tor_exit_nodes"},
}
_ALIASES = {alias: provider for provider, aliases in _REPORTING.items() for alias in aliases}
_EXCLUDED = {alias: role for role, aliases in _NONREPORTING.items() for alias in aliases}
_PLACEHOLDERS = {"unknown", "n/a", "none", "unspecified"}


def source_provenance(source: str) -> dict[str, Any]:
    """Separate raw adapters, reporting publishers and non-reporting context."""
    names = sorted({name.strip().lower() for name in source.split(",")
                    if name.strip() and name.strip().lower() not in _PLACEHOLDERS})
    reporting = sorted({_ALIASES.get(name, f"unmapped:{name}") for name in names if name not in _EXCLUDED})
    excluded = [{"source": name, "role": _EXCLUDED[name]} for name in names if name in _EXCLUDED]
    return {"source_identifiers": names, "reporting_groups": reporting, "excluded_sources": excluded,
            "unmapped_sources": [name for name in names if name not in _ALIASES and name not in _EXCLUDED]}
