# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-10T23:08:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7300 |
| Carried forward | 2898 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 29247 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-10T23:02:07Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 3095 | collected |
| blocklist_de_ssh | 4631 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1739 | collected |
| dshield_block | 20 | collected |
| et_compromised | 600 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4976 | collected |
| ipsum_level5 | 4798 | collected |
| malwarebazaar_recent | 832 | collected |
| nist_nvd_recent | 1722 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1684 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2311 | collected |
| tor_exit_nodes | 1205 | collected |
| urlhaus_recent_urls | 634 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3995 |
| sha256 | 1838 |
| ipv4_cidr | 1683 |
| url | 973 |
| domain | 849 |
| md5 | 227 |
| sha1 | 226 |
| ipv4 | 209 |
