# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-17T17:10:18Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 24605 |
| Carried forward | 247 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 21862 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 70.3 / 88 |
| High-confidence indicators | 7134 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-17T17:09:35Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2373 |
| blocklist_de_ssh | 5361 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 584 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3458 |
| ipsum_level5 | 1578 |
| malwarebazaar_recent | 847 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1630 |
| tor_exit_nodes | 1420 |
| urlhaus_recent_urls | 305 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 6322 |
| cve | 1647 |
| domain | 1274 |
| url | 731 |
| sha256 | 12 |
| md5 | 7 |
| sha1 | 7 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
