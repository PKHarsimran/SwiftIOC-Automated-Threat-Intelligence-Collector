# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-04T06:24:21Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1854 |
| Carried forward | 4768 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 23506 |
| Stored | 10000 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-confidence indicators | 8238 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-04T06:12:12Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1198 |
| blocklist_de_ssh | 4638 |
| ci_army_list | 15000 |
| cisa_kev | 1657 |
| dshield_block | 20 |
| et_compromised | 559 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 0 |
| ipsum_level5 | 1772 |
| malwarebazaar_recent | 655 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1665 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 948 |
| tor_exit_nodes | 1396 |
| urlhaus_recent_urls | 482 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4131 |
| cve | 2280 |
| ipv4_cidr | 1664 |
| url | 686 |
| domain | 334 |
| md5 | 329 |
| sha1 | 284 |
| ipv4 | 195 |
| ja3 | 97 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
