# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-22T10:54:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5323 |
| Carried forward | 2380 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28782 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-22T10:35:46Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 5363 |
| blocklist_de_ssh | 5529 |
| ci_army_list | 15000 |
| cisa_kev | 1717 |
| dshield_block | 20 |
| et_compromised | 690 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 0 |
| ipsum_level5 | 3875 |
| malwarebazaar_recent | 1465 |
| nist_nvd_recent | 1410 |
| openphish_feed | 300 |
| spamhaus_drop | 1712 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 2242 |
| tor_exit_nodes | 1390 |
| urlhaus_recent_urls | 910 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3422 |
| cve | 2862 |
| ipv4_cidr | 1715 |
| url | 1110 |
| domain | 386 |
| sha1 | 249 |
| ipv4 | 215 |
| md5 | 41 |

## Issues

- ⚠️ **greensnow_blocklist**: HTTPSConnectionPool(host='blocklist.greensnow.co', port=443): Max retries exceeded with url: /greensnow.txt (Caused by ReadTimeoutError("HTTPSConnectionPool(host='blocklist.greensnow.co', port=443): Read timed out. (read timeout=20)"))
- ⚠️ **greensnow_blocklist** returned zero indicators
