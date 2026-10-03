# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T15:36:31Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2909 |
| Carried forward | 1648 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27077 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T15:36:17Z |

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
| greensnow_blocklist | 4582 |
| ipsum_level5 | 3528 |
| malwarebazaar_recent | 808 |
| nist_nvd_recent | 1933 |
| openphish_feed | 300 |
| spamhaus_drop | 1693 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4850 |
| tor_exit_nodes | 1390 |
| urlhaus_recent_urls | 705 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2722 |
| cve | 2350 |
| domain | 1976 |
| ipv4_cidr | 1645 |
| url | 956 |
| ipv4 | 182 |
| sha1 | 131 |
| md5 | 38 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
