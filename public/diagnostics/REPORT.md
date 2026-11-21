# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-21T01:02:13Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3318 |
| Carried forward | 1807 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28809 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-21T01:01:39Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 465 | collected |
| blocklist_de_ssh | 5839 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1790 | collected |
| dshield_block | 20 | collected |
| et_compromised | 596 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2285 | collected |
| ipsum_level5 | 3151 | collected |
| malwarebazaar_recent | 1278 | collected |
| nist_nvd_recent | 2600 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1751 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2083 | collected |
| tor_exit_nodes | 1305 | collected |
| urlhaus_recent_urls | 1755 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3322 |
| url | 1987 |
| sha256 | 1911 |
| ipv4_cidr | 1747 |
| ipv4 | 465 |
| domain | 328 |
| md5 | 120 |
| sha1 | 120 |
