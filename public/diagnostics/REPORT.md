# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-29T16:05:48Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4867 |
| Carried forward | 3975 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 34449 |
| Stored | 10000 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-confidence indicators | 7293 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-29T15:57:36Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1062 |
| blocklist_de_ssh | 13188 |
| ci_army_list | 15000 |
| cisa_kev | 1685 |
| dshield_block | 20 |
| et_compromised | 536 |
| feodo_ipblocklist | 0 |
| greensnow_blocklist | 4454 |
| ipsum_level5 | 2800 |
| malwarebazaar_recent | 818 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1706 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1646 |
| tor_exit_nodes | 1423 |
| urlhaus_recent_urls | 406 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3299 |
| cve | 2518 |
| ipv4_cidr | 1705 |
| domain | 1067 |
| url | 601 |
| md5 | 258 |
| sha1 | 252 |
| ipv4 | 203 |
| ja3 | 97 |

## Issues

- ⚠️ **feodo_ipblocklist**: 503 Server Error: certificate has expired for url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
- ⚠️ **feodo_ipblocklist** returned zero indicators
