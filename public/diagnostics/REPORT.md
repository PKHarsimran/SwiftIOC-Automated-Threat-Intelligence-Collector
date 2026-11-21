# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-21T12:00:14Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3204 |
| Carried forward | 1842 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28852 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-21T11:59:56Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 465 | collected |
| blocklist_de_ssh | 5722 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1790 | collected |
| dshield_block | 20 | collected |
| et_compromised | 596 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 1335 | collected |
| ipsum_level5 | 2855 | collected |
| malwarebazaar_recent | 1275 | collected |
| nist_nvd_recent | 3000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1751 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2688 | collected |
| tor_exit_nodes | 1298 | collected |
| urlhaus_recent_urls | 2017 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3322 |
| url | 2226 |
| sha256 | 1834 |
| ipv4_cidr | 1209 |
| domain | 629 |
| ipv4 | 412 |
| md5 | 184 |
| sha1 | 184 |
