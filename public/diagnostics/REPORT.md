# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-01T03:57:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7182 |
| Carried forward | 837 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27924 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-01T03:50:23Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 731 | collected |
| blocklist_de_ssh | 4896 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1766 | collected |
| dshield_block | 20 | collected |
| et_compromised | 542 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3727 | collected |
| ipsum_level5 | 4662 | collected |
| malwarebazaar_recent | 897 | collected |
| nist_nvd_recent | 3000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1756 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3007 | collected |
| tor_exit_nodes | 1228 | collected |
| urlhaus_recent_urls | 2635 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3044 |
| cve | 2334 |
| ipv4_cidr | 1755 |
| sha256 | 1283 |
| domain | 1100 |
| ipv4 | 330 |
| md5 | 77 |
| sha1 | 77 |
