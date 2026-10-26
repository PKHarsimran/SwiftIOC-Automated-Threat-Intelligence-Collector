# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-26T09:42:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5377 |
| Carried forward | 33 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 79490 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-26T09:33:40Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 540 | collected |
| blocklist_de_ssh | 5313 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1756 | collected |
| dshield_block | 20 | collected |
| et_compromised | 482 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 5873 | collected |
| malwarebazaar_recent | 1171 | collected |
| nist_nvd_recent | 9823 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1688 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 7695 | collected |
| tor_exit_nodes | 1211 | collected |
| urlhaus_recent_urls | 43860 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 8001 |
| cve | 1782 |
| sha256 | 141 |
| ipv4 | 35 |
| domain | 28 |
| ipv4_cidr | 13 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
