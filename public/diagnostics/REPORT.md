# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-15T20:45:15Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3123 |
| Carried forward | 2918 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 24950 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-15T20:43:10Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 751 | collected |
| blocklist_de_ssh | 4642 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1781 | collected |
| dshield_block | 20 | collected |
| et_compromised | 584 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 3613 | collected |
| malwarebazaar_recent | 1192 | collected |
| nist_nvd_recent | 635 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1759 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2345 | collected |
| tor_exit_nodes | 1256 | collected |
| urlhaus_recent_urls | 1175 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3142 |
| sha256 | 2300 |
| ipv4_cidr | 1758 |
| url | 1373 |
| domain | 833 |
| md5 | 222 |
| sha1 | 215 |
| ipv4 | 157 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
