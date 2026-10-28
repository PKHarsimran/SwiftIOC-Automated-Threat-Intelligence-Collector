# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-28T03:48:04Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8860 |
| Carried forward | 92 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 56150 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-28T03:40:48Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 522 | collected |
| blocklist_de_ssh | 5333 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1760 | collected |
| dshield_block | 20 | collected |
| et_compromised | 515 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5680 | collected |
| ipsum_level5 | 6086 | collected |
| malwarebazaar_recent | 1681 | collected |
| nist_nvd_recent | 8578 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1760 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3178 | collected |
| tor_exit_nodes | 1231 | collected |
| urlhaus_recent_urls | 23172 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3487 |
| cve | 2512 |
| ipv4_cidr | 1759 |
| sha256 | 1610 |
| domain | 194 |
| md5 | 169 |
| sha1 | 168 |
| ipv4 | 101 |
