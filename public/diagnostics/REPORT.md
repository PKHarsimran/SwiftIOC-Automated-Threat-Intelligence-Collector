# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-27T09:32:41Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6400 |
| Carried forward | 29 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 57869 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-27T09:30:48Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 390 | collected |
| blocklist_de_ssh | 5222 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1758 | collected |
| dshield_block | 20 | collected |
| et_compromised | 504 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5565 | collected |
| ipsum_level5 | 4197 | collected |
| malwarebazaar_recent | 1776 | collected |
| nist_nvd_recent | 0 | failed |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1688 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 7224 | collected |
| tor_exit_nodes | 1225 | collected |
| urlhaus_recent_urls | 29269 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5662 |
| cve | 1758 |
| ipv4_cidr | 1383 |
| sha256 | 843 |
| domain | 121 |
| md5 | 80 |
| sha1 | 79 |
| ipv4 | 74 |

## Issues

- ⚠️ **nist_nvd_recent**: HTTPSConnectionPool(host='services.nvd.nist.gov', port=443): Read timed out.
- ⚠️ **nist_nvd_recent** returned zero indicators
