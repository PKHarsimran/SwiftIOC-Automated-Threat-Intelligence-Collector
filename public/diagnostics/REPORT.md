# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-18T16:54:39Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 23856 |
| Carried forward | 1818 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22605 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 71.9 / 88 |
| High-confidence indicators | 7181 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-18T16:54:32Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2601 |
| blocklist_de_ssh | 5402 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3183 |
| ipsum_level5 | 1692 |
| malwarebazaar_recent | 759 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 793 |
| tor_exit_nodes | 1424 |
| urlhaus_recent_urls | 375 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 5977 |
| cve | 1647 |
| domain | 1460 |
| url | 853 |
| sha256 | 25 |
| md5 | 19 |
| sha1 | 19 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
