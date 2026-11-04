# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-04T15:56:06Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5527 |
| Carried forward | 1265 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30608 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-04T15:55:02Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 758 | collected |
| blocklist_de_ssh | 4536 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1767 | collected |
| dshield_block | 20 | collected |
| et_compromised | 519 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2792 | collected |
| ipsum_level5 | 4410 | collected |
| malwarebazaar_recent | 844 | collected |
| nist_nvd_recent | 2600 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1761 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3401 | collected |
| tor_exit_nodes | 1237 | collected |
| urlhaus_recent_urls | 4823 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3440 |
| cve | 2574 |
| ipv4_cidr | 1760 |
| sha256 | 1233 |
| domain | 476 |
| ipv4 | 195 |
| md5 | 161 |
| sha1 | 161 |
