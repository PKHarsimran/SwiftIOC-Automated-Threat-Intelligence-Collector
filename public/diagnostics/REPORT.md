# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-26T22:41:19Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1720 |
| Carried forward | 3997 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26635 |
| Stored | 10000 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-confidence indicators | 7416 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-26T22:31:07Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 497 |
| blocklist_de_ssh | 5716 |
| ci_army_list | 15000 |
| cisa_kev | 1682 |
| dshield_block | 20 |
| et_compromised | 542 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3067 |
| ipsum_level5 | 951 |
| malwarebazaar_recent | 818 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1704 |
| sslbl_ja3 | 0 |
| threatfox_export_json | 2064 |
| tor_exit_nodes | 1409 |
| urlhaus_recent_urls | 383 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3179 |
| cve | 2586 |
| ipv4_cidr | 1703 |
| url | 884 |
| domain | 717 |
| ipv4 | 430 |
| md5 | 205 |
| sha1 | 199 |
| ja3 | 97 |

## Issues

- ⚠️ **sslbl_ja3**: HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Max retries exceeded with url: /blacklist/ja3_fingerprints.csv (Caused by ReadTimeoutError("HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Read timed out. (read timeout=20)"))
- ⚠️ **sslbl_ja3** returned zero indicators
