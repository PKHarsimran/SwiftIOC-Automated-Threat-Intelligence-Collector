# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-12T05:29:34Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5240 |
| Carried forward | 3074 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 29300 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-12T05:29:09Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1001 | collected |
| blocklist_de_ssh | 4465 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1779 | collected |
| dshield_block | 20 | collected |
| et_compromised | 487 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3377 | collected |
| ipsum_level5 | 3708 | collected |
| malwarebazaar_recent | 1101 | collected |
| nist_nvd_recent | 3000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1756 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2805 | collected |
| tor_exit_nodes | 1258 | collected |
| urlhaus_recent_urls | 1307 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3398 |
| cve | 2383 |
| url | 1459 |
| ipv4_cidr | 1275 |
| domain | 930 |
| md5 | 187 |
| sha1 | 187 |
| ipv4 | 181 |
