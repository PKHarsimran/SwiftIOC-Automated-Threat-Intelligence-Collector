# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-23T04:31:10Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2103 |
| Carried forward | 3733 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22682 |
| Stored | 10000 |
| Score (min / avg / max) | 76 / 79.8 / 96 |
| High-confidence indicators | 7182 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-23T04:31:04Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2918 |
| blocklist_de_ssh | 0 |
| ci_army_list | 15000 |
| cisa_kev | 1674 |
| dshield_block | 20 |
| et_compromised | 544 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3343 |
| ipsum_level5 | 1204 |
| malwarebazaar_recent | 841 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1699 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1533 |
| tor_exit_nodes | 1373 |
| urlhaus_recent_urls | 301 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3483 |
| cve | 2460 |
| ipv4_cidr | 1698 |
| domain | 874 |
| ipv4 | 516 |
| url | 511 |
| md5 | 184 |
| sha1 | 177 |
| ja3 | 97 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
