# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-04T22:40:34Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2775 |
| Carried forward | 1399 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26266 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-04T22:40:20Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1397 |
| blocklist_de_ssh | 0 |
| ci_army_list | 15000 |
| cisa_kev | 1734 |
| dshield_block | 20 |
| et_compromised | 621 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 4274 |
| ipsum_level5 | 3731 |
| malwarebazaar_recent | 978 |
| nist_nvd_recent | 715 |
| openphish_feed | 300 |
| spamhaus_drop | 1692 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4830 |
| tor_exit_nodes | 1384 |
| urlhaus_recent_urls | 864 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3918 |
| cve | 1901 |
| ipv4_cidr | 1691 |
| domain | 1264 |
| url | 1010 |
| ipv4 | 185 |
| sha1 | 26 |
| md5 | 5 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
