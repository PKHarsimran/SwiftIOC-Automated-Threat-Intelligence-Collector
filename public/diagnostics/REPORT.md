# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-31T03:49:04Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7009 |
| Carried forward | 145 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 32970 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-31T03:47:51Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 372 | collected |
| blocklist_de_ssh | 4897 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1766 | collected |
| dshield_block | 20 | collected |
| et_compromised | 542 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3967 | collected |
| ipsum_level5 | 4867 | collected |
| malwarebazaar_recent | 883 | collected |
| nist_nvd_recent | 4000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1757 | collected |
| sslbl_ja3 | 0 | empty |
| threatfox_export_json | 5054 | collected |
| tor_exit_nodes | 1224 | collected |
| urlhaus_recent_urls | 5180 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3102 |
| domain | 2282 |
| cve | 1955 |
| ipv4_cidr | 1377 |
| sha256 | 1057 |
| ipv4 | 227 |

## Issues

- ⚠️ **sslbl_ja3** returned zero indicators
