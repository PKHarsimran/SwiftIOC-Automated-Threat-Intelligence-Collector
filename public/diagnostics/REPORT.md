# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-23T22:52:00Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6675 |
| Carried forward | 44 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 41936 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-23T22:41:21Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 807 | collected |
| blocklist_de_ssh | 4896 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1756 | collected |
| dshield_block | 20 | collected |
| et_compromised | 482 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4558 | collected |
| ipsum_level5 | 5475 | collected |
| malwarebazaar_recent | 1094 | collected |
| nist_nvd_recent | 4200 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1688 | collected |
| sslbl_ja3 | 0 | empty |
| threatfox_export_json | 3287 | collected |
| tor_exit_nodes | 1218 | collected |
| urlhaus_recent_urls | 13781 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5670 |
| cve | 1756 |
| ipv4_cidr | 1687 |
| sha256 | 490 |
| domain | 161 |
| ipv4 | 131 |
| md5 | 53 |
| sha1 | 52 |

## Issues

- ⚠️ **sslbl_ja3** returned zero indicators
