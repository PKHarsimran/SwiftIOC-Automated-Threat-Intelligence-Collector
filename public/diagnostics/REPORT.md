# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-19T09:31:42Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6619 |
| Carried forward | 2849 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30214 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-19T09:24:31Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1065 | collected |
| blocklist_de_ssh | 4185 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1748 | collected |
| dshield_block | 20 | collected |
| et_compromised | 497 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4462 | collected |
| ipsum_level5 | 5306 | collected |
| malwarebazaar_recent | 1130 | collected |
| nist_nvd_recent | 3600 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1692 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3021 | collected |
| tor_exit_nodes | 1203 | collected |
| urlhaus_recent_urls | 653 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2813 |
| cve | 2684 |
| ipv4_cidr | 1691 |
| url | 1465 |
| domain | 798 |
| ipv4 | 217 |
| md5 | 166 |
| sha1 | 166 |
