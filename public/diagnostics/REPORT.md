# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T22:37:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2833 |
| Carried forward | 1573 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26589 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T22:37:07Z |

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
| greensnow_blocklist | 4539 |
| ipsum_level5 | 3528 |
| malwarebazaar_recent | 917 |
| nist_nvd_recent | 1506 |
| openphish_feed | 300 |
| spamhaus_drop | 1692 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 4565 |
| tor_exit_nodes | 1401 |
| urlhaus_recent_urls | 852 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3174 |
| cve | 2244 |
| ipv4_cidr | 1651 |
| domain | 1488 |
| url | 1081 |
| ipv4 | 193 |
| sha1 | 131 |
| md5 | 38 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
