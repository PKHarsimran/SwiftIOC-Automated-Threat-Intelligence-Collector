# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-26T07:07:18Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3502 |
| Carried forward | 2190 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25997 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-26T07:00:06Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 472 | collected |
| blocklist_de_ssh | 4608 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1805 | collected |
| dshield_block | 20 | collected |
| et_compromised | 568 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2705 | collected |
| ipsum_level5 | 3000 | collected |
| malwarebazaar_recent | 1511 | collected |
| nist_nvd_recent | 3443 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1737 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 0 | failed |
| tor_exit_nodes | 1256 | collected |
| urlhaus_recent_urls | 782 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 5306 |
| sha256 | 1950 |
| ipv4_cidr | 1736 |
| url | 782 |
| md5 | 100 |
| sha1 | 100 |
| ipv4 | 26 |

## Issues

- ⚠️ **threatfox_export_json**: Response ended prematurely
- ⚠️ **threatfox_export_json** returned zero indicators
