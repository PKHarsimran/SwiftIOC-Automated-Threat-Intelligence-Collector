# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-30T03:13:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5431 |
| Carried forward | 4157 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 34919 |
| Stored | 10000 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-confidence indicators | 7210 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-30T03:02:06Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1297 |
| blocklist_de_ssh | 13096 |
| ci_army_list | 15000 |
| cisa_kev | 1685 |
| dshield_block | 20 |
| et_compromised | 536 |
| feodo_ipblocklist | 0 |
| greensnow_blocklist | 5266 |
| ipsum_level5 | 2790 |
| malwarebazaar_recent | 836 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1706 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1548 |
| tor_exit_nodes | 1430 |
| urlhaus_recent_urls | 386 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3440 |
| cve | 2666 |
| ipv4_cidr | 1705 |
| domain | 903 |
| url | 529 |
| md5 | 247 |
| sha1 | 240 |
| ipv4 | 173 |
| ja3 | 97 |

## Issues

- ⚠️ **feodo_ipblocklist**: 503 Server Error: certificate has expired for url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
- ⚠️ **feodo_ipblocklist** returned zero indicators
