# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-29T22:13:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4828 |
| Carried forward | 3947 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 34323 |
| Stored | 10000 |
| Score (min / avg / max) | 77 / 79.8 / 96 |
| High-confidence indicators | 7019 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-29T22:08:30Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1062 |
| blocklist_de_ssh | 13139 |
| ci_army_list | 15000 |
| cisa_kev | 1685 |
| dshield_block | 20 |
| et_compromised | 536 |
| feodo_ipblocklist | 0 |
| greensnow_blocklist | 4363 |
| ipsum_level5 | 2800 |
| malwarebazaar_recent | 811 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1706 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1652 |
| tor_exit_nodes | 1430 |
| urlhaus_recent_urls | 403 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3387 |
| cve | 2518 |
| ipv4_cidr | 1705 |
| domain | 1036 |
| url | 557 |
| md5 | 258 |
| sha1 | 252 |
| ipv4 | 190 |
| ja3 | 97 |

## Issues

- ⚠️ **feodo_ipblocklist**: 503 Server Error: certificate has expired for url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
- ⚠️ **feodo_ipblocklist** returned zero indicators
