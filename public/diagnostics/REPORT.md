# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-10T12:02:23Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4905 |
| Carried forward | 2305 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27177 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-10T12:01:14Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 624 | collected |
| blocklist_de_ssh | 4400 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1773 | collected |
| dshield_block | 20 | collected |
| et_compromised | 506 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2692 | collected |
| ipsum_level5 | 3552 | collected |
| malwarebazaar_recent | 2249 | collected |
| nist_nvd_recent | 2200 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1764 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2094 | collected |
| tor_exit_nodes | 1250 | collected |
| urlhaus_recent_urls | 1251 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3042 |
| cve | 2817 |
| ipv4_cidr | 1763 |
| url | 1386 |
| domain | 401 |
| md5 | 218 |
| sha1 | 218 |
| ipv4 | 155 |
