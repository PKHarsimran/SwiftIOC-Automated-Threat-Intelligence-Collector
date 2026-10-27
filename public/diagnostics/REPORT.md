# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-27T03:26:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6744 |
| Carried forward | 32 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 75063 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-27T03:22:29Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 390 | collected |
| blocklist_de_ssh | 5171 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1758 | collected |
| dshield_block | 20 | collected |
| et_compromised | 504 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5450 | collected |
| ipsum_level5 | 4197 | collected |
| malwarebazaar_recent | 1390 | collected |
| nist_nvd_recent | 3400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1688 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 7432 | collected |
| tor_exit_nodes | 1229 | collected |
| urlhaus_recent_urls | 43744 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5545 |
| cve | 1758 |
| ipv4_cidr | 1687 |
| sha256 | 635 |
| domain | 134 |
| ipv4 | 83 |
| md5 | 79 |
| sha1 | 79 |
