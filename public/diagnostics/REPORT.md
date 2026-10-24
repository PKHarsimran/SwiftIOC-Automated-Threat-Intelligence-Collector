# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-24T18:33:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6734 |
| Carried forward | 28 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 59282 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-24T18:31:51Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1145 | collected |
| blocklist_de_ssh | 4672 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1756 | collected |
| dshield_block | 20 | collected |
| et_compromised | 482 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4533 | collected |
| ipsum_level5 | 5289 | collected |
| malwarebazaar_recent | 694 | collected |
| nist_nvd_recent | 2400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1688 | collected |
| sslbl_ja3 | 0 | empty |
| threatfox_export_json | 2859 | collected |
| tor_exit_nodes | 1210 | collected |
| urlhaus_recent_urls | 33935 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5961 |
| cve | 1756 |
| ipv4_cidr | 1687 |
| sha256 | 237 |
| domain | 130 |
| md5 | 77 |
| ipv4 | 76 |
| sha1 | 76 |

## Issues

- ⚠️ **sslbl_ja3** returned zero indicators
