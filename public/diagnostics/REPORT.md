# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-12T20:48:32Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7068 |
| Carried forward | 2531 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30174 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-12T20:38:17Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 3698 | collected |
| blocklist_de_ssh | 4710 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1739 | collected |
| dshield_block | 20 | collected |
| et_compromised | 600 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4866 | collected |
| ipsum_level5 | 4723 | collected |
| malwarebazaar_recent | 1014 | collected |
| nist_nvd_recent | 2167 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1677 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 1809 | collected |
| tor_exit_nodes | 1205 | collected |
| urlhaus_recent_urls | 1081 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3954 |
| sha256 | 1972 |
| ipv4_cidr | 1676 |
| url | 1488 |
| ipv4 | 322 |
| domain | 299 |
| md5 | 145 |
| sha1 | 144 |
