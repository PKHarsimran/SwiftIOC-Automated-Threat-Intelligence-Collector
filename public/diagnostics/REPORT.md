# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-05T08:58:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3594 |
| Carried forward | 2207 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26932 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.9 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-05T08:47:20Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 1677 |
| blocklist_de_ssh | 0 |
| ci_army_list | 15000 |
| cisa_kev | 1734 |
| dshield_block | 20 |
| et_compromised | 621 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 5325 |
| ipsum_level5 | 3531 |
| malwarebazaar_recent | 1059 |
| nist_nvd_recent | 769 |
| openphish_feed | 300 |
| spamhaus_drop | 1692 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4196 |
| tor_exit_nodes | 1380 |
| urlhaus_recent_urls | 913 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4121 |
| cve | 2255 |
| ipv4_cidr | 1691 |
| url | 1089 |
| domain | 518 |
| ipv4 | 182 |
| md5 | 74 |
| sha1 | 70 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
