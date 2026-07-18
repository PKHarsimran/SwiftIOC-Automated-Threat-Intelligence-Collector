# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-18T09:21:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 24587 |
| Carried forward | 1583 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22833 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 71.9 / 88 |
| High-confidence indicators | 7120 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-18T09:21:32Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2601 |
| blocklist_de_ssh | 5356 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3927 |
| ipsum_level5 | 1692 |
| malwarebazaar_recent | 792 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 809 |
| tor_exit_nodes | 1423 |
| urlhaus_recent_urls | 360 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 5905 |
| cve | 1647 |
| domain | 1403 |
| url | 983 |
| sha256 | 24 |
| md5 | 19 |
| sha1 | 19 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
