# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-10T02:30:00Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5419 |
| Carried forward | 3179 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28726 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-10T02:29:46Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 624 | collected |
| blocklist_de_ssh | 4299 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1773 | collected |
| dshield_block | 20 | collected |
| et_compromised | 506 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3277 | collected |
| ipsum_level5 | 3552 | collected |
| malwarebazaar_recent | 2077 | collected |
| nist_nvd_recent | 2227 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1764 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2292 | collected |
| tor_exit_nodes | 1250 | collected |
| urlhaus_recent_urls | 1903 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2832 |
| sha256 | 2612 |
| url | 2194 |
| ipv4_cidr | 1332 |
| domain | 446 |
| md5 | 218 |
| sha1 | 218 |
| ipv4 | 148 |
