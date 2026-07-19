# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-19T16:52:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3472 |
| Carried forward | 1622 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 23827 |
| Stored | 10000 |
| Score (min / avg / max) | 68 / 75.3 / 88 |
| High-confidence indicators | 8548 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-19T16:52:47Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2819 |
| blocklist_de_ssh | 4974 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 2893 |
| ipsum_level5 | 2279 |
| malwarebazaar_recent | 657 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| spamhaus_drop | 1678 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 949 |
| tor_exit_nodes | 1423 |
| urlhaus_recent_urls | 378 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4593 |
| ipv4_cidr | 1677 |
| cve | 1647 |
| domain | 1615 |
| url | 326 |
| sha256 | 60 |
| md5 | 41 |
| sha1 | 41 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
