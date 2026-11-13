# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-13T19:06:14Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4315 |
| Carried forward | 3101 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26128 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-13T19:05:51Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 343 | collected |
| blocklist_de_ssh | 4805 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1781 | collected |
| dshield_block | 20 | collected |
| et_compromised | 566 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2564 | collected |
| ipsum_level5 | 3855 | collected |
| malwarebazaar_recent | 1042 | collected |
| nist_nvd_recent | 200 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1759 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3123 | collected |
| tor_exit_nodes | 1254 | collected |
| urlhaus_recent_urls | 628 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2933 |
| cve | 2455 |
| ipv4_cidr | 1758 |
| domain | 1390 |
| url | 771 |
| md5 | 282 |
| sha1 | 275 |
| ipv4 | 136 |
