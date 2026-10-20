# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-20T03:11:29Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8181 |
| Carried forward | 2981 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 36977 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-20T03:04:11Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1465 | collected |
| blocklist_de_ssh | 5286 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1748 | collected |
| dshield_block | 20 | collected |
| et_compromised | 474 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5286 | collected |
| ipsum_level5 | 5407 | collected |
| malwarebazaar_recent | 1247 | collected |
| nist_nvd_recent | 9800 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1693 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2642 | collected |
| tor_exit_nodes | 1209 | collected |
| urlhaus_recent_urls | 498 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3125 |
| sha256 | 2879 |
| ipv4_cidr | 1692 |
| url | 1265 |
| domain | 556 |
| ipv4 | 231 |
| md5 | 127 |
| sha1 | 125 |
