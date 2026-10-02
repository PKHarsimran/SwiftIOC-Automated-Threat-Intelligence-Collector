# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-02T23:31:01Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3497 |
| Carried forward | 2561 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27147 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-02T23:23:26Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 672 |
| blocklist_de_ssh | 0 |
| ci_army_list | 15000 |
| cisa_kev | 1733 |
| dshield_block | 20 |
| et_compromised | 621 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 5685 |
| ipsum_level5 | 4372 |
| malwarebazaar_recent | 1159 |
| nist_nvd_recent | 1877 |
| openphish_feed | 300 |
| spamhaus_drop | 1693 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 2720 |
| tor_exit_nodes | 1374 |
| urlhaus_recent_urls | 755 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2855 |
| cve | 2772 |
| ipv4_cidr | 1692 |
| domain | 1153 |
| url | 1105 |
| ipv4 | 212 |
| sha1 | 159 |
| md5 | 52 |

## Issues

- ⚠️ **blocklist_de_ssh** returned zero indicators
