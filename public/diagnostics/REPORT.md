# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-13T11:49:33Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3979 |
| Carried forward | 3240 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28200 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-13T11:42:58Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 343 | collected |
| blocklist_de_ssh | 4717 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1779 | collected |
| dshield_block | 20 | collected |
| et_compromised | 566 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 1762 | collected |
| ipsum_level5 | 3855 | collected |
| malwarebazaar_recent | 1089 | collected |
| nist_nvd_recent | 2800 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1758 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2929 | collected |
| tor_exit_nodes | 1254 | collected |
| urlhaus_recent_urls | 665 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3118 |
| cve | 2412 |
| ipv4_cidr | 1757 |
| domain | 1318 |
| url | 810 |
| md5 | 219 |
| sha1 | 212 |
| ipv4 | 154 |
