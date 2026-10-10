# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-10T10:32:19Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6559 |
| Carried forward | 3205 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30039 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-10T10:31:57Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 3095 | collected |
| blocklist_de_ssh | 4306 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1739 | collected |
| dshield_block | 20 | collected |
| et_compromised | 600 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3153 | collected |
| ipsum_level5 | 4798 | collected |
| malwarebazaar_recent | 894 | collected |
| nist_nvd_recent | 3000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1684 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2853 | collected |
| tor_exit_nodes | 1205 | collected |
| urlhaus_recent_urls | 644 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3749 |
| sha256 | 1763 |
| ipv4_cidr | 1683 |
| domain | 1235 |
| url | 974 |
| ipv4 | 259 |
| md5 | 169 |
| sha1 | 168 |
