# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-03T05:02:17Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7180 |
| Carried forward | 766 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 29133 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-03T05:01:10Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 344 | collected |
| blocklist_de_ssh | 4850 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1766 | collected |
| dshield_block | 20 | collected |
| et_compromised | 518 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3783 | collected |
| ipsum_level5 | 4456 | collected |
| malwarebazaar_recent | 947 | collected |
| nist_nvd_recent | 1697 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1757 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 4907 | collected |
| tor_exit_nodes | 1240 | collected |
| urlhaus_recent_urls | 3860 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3812 |
| cve | 2276 |
| domain | 1064 |
| sha256 | 963 |
| ipv4 | 876 |
| ipv4_cidr | 875 |
| md5 | 67 |
| sha1 | 67 |
