# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-30T04:03:51Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7785 |
| Carried forward | 423 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 31829 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-30T04:01:01Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 820 | collected |
| blocklist_de_ssh | 4878 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1764 | collected |
| dshield_block | 20 | collected |
| et_compromised | 536 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4275 | collected |
| ipsum_level5 | 5012 | collected |
| malwarebazaar_recent | 981 | collected |
| nist_nvd_recent | 0 | failed |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1757 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 5683 | collected |
| tor_exit_nodes | 1225 | collected |
| urlhaus_recent_urls | 6838 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 4001 |
| domain | 1907 |
| cve | 1764 |
| ipv4_cidr | 1416 |
| sha256 | 597 |
| ipv4 | 139 |
| md5 | 88 |
| sha1 | 88 |

## Issues

- ⚠️ **nist_nvd_recent**: HTTPSConnectionPool(host='services.nvd.nist.gov', port=443): Read timed out.
- ⚠️ **nist_nvd_recent** returned zero indicators
