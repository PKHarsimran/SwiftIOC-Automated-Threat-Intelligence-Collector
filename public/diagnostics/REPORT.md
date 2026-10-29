# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-29T20:49:29Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7304 |
| Carried forward | 184 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 33798 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-29T20:47:59Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 430 | collected |
| blocklist_de_ssh | 4932 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1764 | collected |
| dshield_block | 20 | collected |
| et_compromised | 524 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3749 | collected |
| ipsum_level5 | 5728 | collected |
| malwarebazaar_recent | 1062 | collected |
| nist_nvd_recent | 3000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1757 | collected |
| sslbl_ja3 | 0 | failed |
| threatfox_export_json | 3946 | collected |
| tor_exit_nodes | 1227 | collected |
| urlhaus_recent_urls | 7474 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3737 |
| cve | 2070 |
| ipv4_cidr | 1756 |
| sha256 | 1134 |
| domain | 768 |
| ipv4 | 201 |
| md5 | 167 |
| sha1 | 167 |

## Issues

- ⚠️ **sslbl_ja3**: HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Max retries exceeded with url: /blacklist/ja3_fingerprints.csv (Caused by ReadTimeoutError("HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Read timed out. (read timeout=20)"))
- ⚠️ **sslbl_ja3** returned zero indicators
