# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-21T19:02:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3338 |
| Carried forward | 1664 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28538 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-21T19:02:33Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 465 | collected |
| blocklist_de_ssh | 5696 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1790 | collected |
| dshield_block | 20 | collected |
| et_compromised | 596 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 1921 | collected |
| ipsum_level5 | 2855 | collected |
| malwarebazaar_recent | 1178 | collected |
| nist_nvd_recent | 2400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1752 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2817 | collected |
| tor_exit_nodes | 1292 | collected |
| urlhaus_recent_urls | 2028 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3284 |
| url | 2146 |
| sha256 | 1607 |
| ipv4_cidr | 1325 |
| domain | 659 |
| ipv4 | 579 |
| md5 | 200 |
| sha1 | 200 |
