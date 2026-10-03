# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T03:29:50Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3436 |
| Carried forward | 1560 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25841 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T03:17:14Z |

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
| greensnow_blocklist | 5627 |
| ipsum_level5 | 3528 |
| malwarebazaar_recent | 1174 |
| nist_nvd_recent | 1889 |
| openphish_feed | 300 |
| spamhaus_drop | 1693 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 2839 |
| tor_exit_nodes | 1375 |
| urlhaus_recent_urls | 743 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3016 |
| cve | 2694 |
| ipv4_cidr | 1613 |
| domain | 1157 |
| url | 1101 |
| ipv4 | 223 |
| sha1 | 144 |
| md5 | 52 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
