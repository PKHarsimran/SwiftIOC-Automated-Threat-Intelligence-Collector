# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-23T05:23:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2596 |
| Carried forward | 3032 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25400 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-23T05:17:49Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 611 | collected |
| blocklist_de_ssh | 4794 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1790 | collected |
| dshield_block | 20 | collected |
| et_compromised | 596 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2223 | collected |
| ipsum_level5 | 2609 | collected |
| malwarebazaar_recent | 1452 | collected |
| nist_nvd_recent | 745 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1752 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 0 | failed |
| tor_exit_nodes | 1250 | collected |
| urlhaus_recent_urls | 1720 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3796 |
| sha256 | 2407 |
| ipv4_cidr | 1751 |
| url | 1720 |
| md5 | 151 |
| sha1 | 151 |
| ipv4 | 24 |

## Issues

- ⚠️ **threatfox_export_json**: Response ended prematurely
- ⚠️ **threatfox_export_json** returned zero indicators
