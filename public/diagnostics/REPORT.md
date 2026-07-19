# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-19T13:06:08Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3447 |
| Carried forward | 1625 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 23714 |
| Stored | 10000 |
| Score (min / avg / max) | 67 / 75.4 / 88 |
| High-confidence indicators | 8548 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-19T13:06:01Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2819 |
| blocklist_de_ssh | 4969 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 2886 |
| ipsum_level5 | 2279 |
| malwarebazaar_recent | 605 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| spamhaus_drop | 1678 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 927 |
| tor_exit_nodes | 1422 |
| urlhaus_recent_urls | 324 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4621 |
| ipv4_cidr | 1677 |
| cve | 1647 |
| domain | 1587 |
| url | 326 |
| sha256 | 60 |
| md5 | 41 |
| sha1 | 41 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
