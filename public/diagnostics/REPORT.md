# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-14T11:09:51Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3007 |
| Carried forward | 3556 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25020 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-14T11:09:18Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 324 | collected |
| blocklist_de_ssh | 4857 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1781 | collected |
| dshield_block | 20 | collected |
| et_compromised | 584 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 3322 | collected |
| malwarebazaar_recent | 1172 | collected |
| nist_nvd_recent | 400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1759 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2793 | collected |
| tor_exit_nodes | 1260 | collected |
| urlhaus_recent_urls | 797 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2746 |
| sha256 | 2721 |
| ipv4_cidr | 1758 |
| domain | 1302 |
| url | 905 |
| md5 | 213 |
| sha1 | 206 |
| ipv4 | 149 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
