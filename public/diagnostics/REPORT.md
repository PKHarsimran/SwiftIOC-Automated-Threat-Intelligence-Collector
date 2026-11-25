# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-25T23:57:34Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3191 |
| Carried forward | 4502 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27248 |
| Stored | 10000 |
| Score (min / avg / max) | 77 / 80.1 / 96 |
| High-confidence indicators | 8878 |
| Earliest first_seen | 2004-12-06T05:00:00Z |
| Newest first_seen | 2026-11-25T23:47:06Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 460 | collected |
| blocklist_de_ssh | 4672 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1805 | collected |
| dshield_block | 20 | collected |
| et_compromised | 568 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2299 | collected |
| ipsum_level5 | 2966 | collected |
| malwarebazaar_recent | 1545 | collected |
| nist_nvd_recent | 2400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1737 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 0 | failed |
| tor_exit_nodes | 1255 | collected |
| urlhaus_recent_urls | 808 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4202 |
| sha256 | 1803 |
| ipv4_cidr | 1736 |
| url | 973 |
| ipv4 | 695 |
| domain | 294 |
| md5 | 100 |
| sha1 | 100 |
| ja3 | 97 |

## Issues

- ⚠️ **threatfox_export_json**: Response ended prematurely
- ⚠️ **threatfox_export_json** returned zero indicators
