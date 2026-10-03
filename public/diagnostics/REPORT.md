# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T09:36:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3385 |
| Carried forward | 1821 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27738 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T09:36:29Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1073 |
| blocklist_de_ssh | 0 |
| ci_army_list | 15000 |
| cisa_kev | 1733 |
| dshield_block | 20 |
| et_compromised | 621 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 5533 |
| ipsum_level5 | 3528 |
| malwarebazaar_recent | 1147 |
| nist_nvd_recent | 1799 |
| openphish_feed | 300 |
| spamhaus_drop | 1693 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4669 |
| tor_exit_nodes | 1379 |
| urlhaus_recent_urls | 705 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2785 |
| cve | 2455 |
| domain | 1928 |
| ipv4_cidr | 1483 |
| url | 970 |
| ipv4 | 174 |
| sha1 | 149 |
| md5 | 56 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
