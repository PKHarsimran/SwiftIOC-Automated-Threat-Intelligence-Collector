# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-13T05:08:48Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8195 |
| Carried forward | 2375 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 29890 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-13T05:05:15Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 3918 | collected |
| blocklist_de_ssh | 4301 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1739 | collected |
| dshield_block | 20 | collected |
| et_compromised | 529 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5490 | collected |
| ipsum_level5 | 5079 | collected |
| malwarebazaar_recent | 1040 | collected |
| nist_nvd_recent | 2000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1677 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2164 | collected |
| tor_exit_nodes | 1209 | collected |
| urlhaus_recent_urls | 1142 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3647 |
| sha256 | 1917 |
| url | 1856 |
| ipv4_cidr | 1676 |
| ipv4 | 327 |
| domain | 274 |
| md5 | 152 |
| sha1 | 151 |
