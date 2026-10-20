# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-20T22:53:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7357 |
| Carried forward | 2908 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30057 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-20T22:53:22Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1465 | collected |
| blocklist_de_ssh | 5350 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1754 | collected |
| dshield_block | 20 | collected |
| et_compromised | 481 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4729 | collected |
| ipsum_level5 | 5407 | collected |
| malwarebazaar_recent | 1435 | collected |
| nist_nvd_recent | 2000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1687 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2867 | collected |
| tor_exit_nodes | 1210 | collected |
| urlhaus_recent_urls | 699 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3144 |
| sha256 | 2789 |
| url | 1648 |
| ipv4_cidr | 1588 |
| ipv4 | 235 |
| domain | 232 |
| md5 | 183 |
| sha1 | 181 |
