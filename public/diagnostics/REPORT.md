# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-15T15:15:39Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3202 |
| Carried forward | 3491 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26111 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-15T15:10:34Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 751 | collected |
| blocklist_de_ssh | 4695 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1781 | collected |
| dshield_block | 20 | collected |
| et_compromised | 584 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 3613 | collected |
| malwarebazaar_recent | 1106 | collected |
| nist_nvd_recent | 1400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1759 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2227 | collected |
| tor_exit_nodes | 1258 | collected |
| urlhaus_recent_urls | 1226 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3039 |
| sha256 | 2618 |
| ipv4_cidr | 1758 |
| url | 1324 |
| domain | 672 |
| md5 | 222 |
| sha1 | 215 |
| ipv4 | 152 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
