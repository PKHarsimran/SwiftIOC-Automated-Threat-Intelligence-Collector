# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-04T03:57:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3651 |
| Carried forward | 1353 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26942 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-04T03:57:39Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1397 |
| blocklist_de_ssh | 0 |
| ci_army_list | 15000 |
| cisa_kev | 1733 |
| dshield_block | 20 |
| et_compromised | 621 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 5405 |
| ipsum_level5 | 3731 |
| malwarebazaar_recent | 983 |
| nist_nvd_recent | 1352 |
| openphish_feed | 300 |
| spamhaus_drop | 1692 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4686 |
| tor_exit_nodes | 1398 |
| urlhaus_recent_urls | 820 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3530 |
| cve | 2255 |
| domain | 1453 |
| ipv4_cidr | 1416 |
| url | 1050 |
| ipv4 | 189 |
| sha1 | 69 |
| md5 | 38 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
