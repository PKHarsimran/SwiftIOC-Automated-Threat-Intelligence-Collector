# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-23T19:45:26Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4272 |
| Carried forward | 3756 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 31200 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-23T19:45:01Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 611 | collected |
| blocklist_de_ssh | 4763 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1790 | collected |
| dshield_block | 20 | collected |
| et_compromised | 596 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2828 | collected |
| ipsum_level5 | 2609 | collected |
| malwarebazaar_recent | 1499 | collected |
| nist_nvd_recent | 2178 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1752 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 5559 | collected |
| tor_exit_nodes | 1253 | collected |
| urlhaus_recent_urls | 856 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2828 |
| sha256 | 2305 |
| ipv4 | 1960 |
| ipv4_cidr | 1209 |
| url | 923 |
| domain | 460 |
| sha1 | 160 |
| md5 | 155 |
