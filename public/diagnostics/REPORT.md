# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-21T03:01:47Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7509 |
| Carried forward | 2534 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27271 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-21T03:01:07Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 251 | collected |
| blocklist_de_ssh | 5376 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1754 | collected |
| dshield_block | 20 | collected |
| et_compromised | 481 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5506 | collected |
| ipsum_level5 | 5316 | collected |
| malwarebazaar_recent | 1542 | collected |
| nist_nvd_recent | 0 | failed |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1687 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3025 | collected |
| tor_exit_nodes | 1208 | collected |
| urlhaus_recent_urls | 678 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3144 |
| sha256 | 2728 |
| ipv4_cidr | 1661 |
| url | 1641 |
| domain | 321 |
| ipv4 | 247 |
| md5 | 130 |
| sha1 | 128 |

## Issues

- ⚠️ **nist_nvd_recent**: HTTPSConnectionPool(host='services.nvd.nist.gov', port=443): Read timed out.
- ⚠️ **nist_nvd_recent** returned zero indicators
