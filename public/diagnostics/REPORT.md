# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-13T08:43:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5188 |
| Carried forward | 961 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 32129 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.5 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-13T08:35:16Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 3373 |
| blocklist_de_ssh | 11363 |
| ci_army_list | 15000 |
| cisa_kev | 1709 |
| dshield_block | 20 |
| et_compromised | 610 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 0 |
| ipsum_level5 | 4677 |
| malwarebazaar_recent | 385 |
| nist_nvd_recent | 1461 |
| openphish_feed | 300 |
| spamhaus_drop | 1723 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4008 |
| tor_exit_nodes | 1330 |
| urlhaus_recent_urls | 295 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3241 |
| cve | 3050 |
| ipv4_cidr | 1722 |
| domain | 704 |
| url | 503 |
| sha1 | 348 |
| ipv4 | 292 |
| md5 | 140 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
