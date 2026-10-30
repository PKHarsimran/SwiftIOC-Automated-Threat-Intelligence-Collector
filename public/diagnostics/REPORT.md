# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-30T14:47:26Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6879 |
| Carried forward | 44 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 33222 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-30T14:45:51Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 820 | collected |
| blocklist_de_ssh | 4860 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1764 | collected |
| dshield_block | 20 | collected |
| et_compromised | 536 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3483 | collected |
| ipsum_level5 | 5012 | collected |
| malwarebazaar_recent | 1013 | collected |
| nist_nvd_recent | 3400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1757 | collected |
| sslbl_ja3 | 0 | failed |
| threatfox_export_json | 5386 | collected |
| tor_exit_nodes | 1227 | collected |
| urlhaus_recent_urls | 5474 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3365 |
| domain | 1910 |
| cve | 1764 |
| ipv4_cidr | 1756 |
| sha256 | 840 |
| ipv4 | 189 |
| md5 | 88 |
| sha1 | 88 |

## Issues

- ⚠️ **sslbl_ja3**: HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Max retries exceeded with url: /blacklist/ja3_fingerprints.csv (Caused by ReadTimeoutError("HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Read timed out. (read timeout=20)"))
- ⚠️ **sslbl_ja3** returned zero indicators
