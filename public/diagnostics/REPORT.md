# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-03T22:10:31Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2838 |
| Carried forward | 4218 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30023 |
| Stored | 10000 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-confidence indicators | 6903 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-03T22:05:08Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 715 |
| blocklist_de_ssh | 11291 |
| ci_army_list | 15000 |
| cisa_kev | 1694 |
| dshield_block | 20 |
| et_compromised | 544 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 0 |
| ipsum_level5 | 3111 |
| malwarebazaar_recent | 691 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1710 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1351 |
| tor_exit_nodes | 1400 |
| urlhaus_recent_urls | 514 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3135 |
| sha256 | 2904 |
| ipv4_cidr | 1709 |
| url | 973 |
| domain | 566 |
| ipv4 | 231 |
| md5 | 193 |
| sha1 | 192 |
| ja3 | 97 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
