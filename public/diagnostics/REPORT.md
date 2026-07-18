# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-18T02:04:42Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 25806 |
| Carried forward | 1018 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 23280 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 71.8 / 88 |
| High-confidence indicators | 8030 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-18T02:03:06Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2601 |
| blocklist_de_ssh | 5363 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 4007 |
| ipsum_level5 | 1692 |
| malwarebazaar_recent | 886 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1862 |
| tor_exit_nodes | 1421 |
| urlhaus_recent_urls | 347 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 6592 |
| cve | 1647 |
| domain | 1370 |
| url | 329 |
| sha256 | 24 |
| md5 | 19 |
| sha1 | 19 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
