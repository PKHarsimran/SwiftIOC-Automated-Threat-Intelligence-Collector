# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-19T02:12:20Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4216 |
| Carried forward | 2412 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25248 |
| Stored | 10000 |
| Score (min / avg / max) | 68 / 75.5 / 88 |
| High-confidence indicators | 8579 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-19T02:11:47Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2819 |
| blocklist_de_ssh | 5534 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3775 |
| ipsum_level5 | 2279 |
| malwarebazaar_recent | 692 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| spamhaus_drop | 1678 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 888 |
| tor_exit_nodes | 1422 |
| urlhaus_recent_urls | 338 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4681 |
| ipv4_cidr | 1677 |
| cve | 1647 |
| domain | 1527 |
| url | 340 |
| sha256 | 46 |
| md5 | 41 |
| sha1 | 41 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
