# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-19T06:26:17Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3972 |
| Carried forward | 1593 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 24696 |
| Stored | 10000 |
| Score (min / avg / max) | 68 / 75.4 / 88 |
| High-confidence indicators | 8596 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-19T06:26:01Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2819 |
| blocklist_de_ssh | 5648 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3698 |
| ipsum_level5 | 2279 |
| malwarebazaar_recent | 667 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| spamhaus_drop | 1678 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 890 |
| tor_exit_nodes | 1422 |
| urlhaus_recent_urls | 347 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4690 |
| ipv4_cidr | 1677 |
| cve | 1647 |
| domain | 1542 |
| url | 316 |
| sha256 | 46 |
| md5 | 41 |
| sha1 | 41 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
