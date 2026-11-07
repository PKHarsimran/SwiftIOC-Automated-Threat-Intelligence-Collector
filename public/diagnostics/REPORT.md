# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-07T23:21:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5756 |
| Carried forward | 2085 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28968 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-07T23:17:41Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1332 | collected |
| blocklist_de_ssh | 4494 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1769 | collected |
| dshield_block | 20 | collected |
| et_compromised | 511 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2867 | collected |
| ipsum_level5 | 4471 | collected |
| malwarebazaar_recent | 1024 | collected |
| nist_nvd_recent | 3400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1764 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3169 | collected |
| tor_exit_nodes | 1240 | collected |
| urlhaus_recent_urls | 1176 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3649 |
| cve | 2927 |
| url | 1400 |
| ipv4_cidr | 700 |
| domain | 400 |
| md5 | 330 |
| sha1 | 330 |
| ipv4 | 264 |
