# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-31T16:42:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4090 |
| Carried forward | 250 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28789 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-31T16:42:32Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 372 | collected |
| blocklist_de_ssh | 4934 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1766 | collected |
| dshield_block | 20 | collected |
| et_compromised | 542 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 4867 | collected |
| malwarebazaar_recent | 960 | collected |
| nist_nvd_recent | 2600 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1756 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 4713 | collected |
| tor_exit_nodes | 1221 | collected |
| urlhaus_recent_urls | 3476 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3587 |
| cve | 1898 |
| ipv4_cidr | 1580 |
| sha256 | 1344 |
| domain | 1299 |
| ipv4 | 292 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
