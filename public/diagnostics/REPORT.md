# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-26T18:56:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8424 |
| Carried forward | 4721 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 32345 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-26T18:47:19Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 6160 |
| blocklist_de_ssh | 5056 |
| ci_army_list | 15000 |
| cisa_kev | 1726 |
| dshield_block | 20 |
| et_compromised | 669 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 4856 |
| ipsum_level5 | 4856 |
| malwarebazaar_recent | 1332 |
| nist_nvd_recent | 2400 |
| openphish_feed | 300 |
| spamhaus_drop | 1711 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 0 |
| tor_exit_nodes | 1383 |
| urlhaus_recent_urls | 477 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 5097 |
| sha256 | 2442 |
| ipv4_cidr | 1710 |
| url | 479 |
| sha1 | 228 |
| ipv4 | 24 |
| md5 | 20 |

## Issues

- ⚠️ **threatfox_export_json**: Expecting value: line 1 column 1 (char 0)
- ⚠️ **threatfox_export_json** returned zero indicators
