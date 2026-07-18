# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-18T13:06:10Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 23863 |
| Carried forward | 1849 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22586 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 72.0 / 88 |
| High-confidence indicators | 7150 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-18T13:06:05Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2601 |
| blocklist_de_ssh | 5331 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3244 |
| ipsum_level5 | 1692 |
| malwarebazaar_recent | 782 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 795 |
| tor_exit_nodes | 1423 |
| urlhaus_recent_urls | 368 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 6529 |
| cve | 1647 |
| domain | 1431 |
| url | 331 |
| sha256 | 24 |
| md5 | 19 |
| sha1 | 19 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
