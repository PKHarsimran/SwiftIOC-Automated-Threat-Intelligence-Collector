# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-24T03:02:59Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5139 |
| Carried forward | 39 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 41318 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-24T02:55:02Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1145 | collected |
| blocklist_de_ssh | 4922 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1756 | collected |
| dshield_block | 20 | collected |
| et_compromised | 482 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 5289 | collected |
| malwarebazaar_recent | 1004 | collected |
| nist_nvd_recent | 6600 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1688 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3156 | collected |
| tor_exit_nodes | 1218 | collected |
| urlhaus_recent_urls | 13736 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5577 |
| cve | 1756 |
| ipv4_cidr | 1687 |
| sha256 | 566 |
| domain | 170 |
| ipv4 | 139 |
| md5 | 53 |
| sha1 | 52 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
