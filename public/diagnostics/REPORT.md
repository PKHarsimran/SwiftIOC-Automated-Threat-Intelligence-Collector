# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-11T22:26:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4680 |
| Carried forward | 2770 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 28740 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-11T22:25:55Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 653 | collected |
| blocklist_de_ssh | 4462 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1779 | collected |
| dshield_block | 20 | collected |
| et_compromised | 487 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2798 | collected |
| ipsum_level5 | 3423 | collected |
| malwarebazaar_recent | 1386 | collected |
| nist_nvd_recent | 3200 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1756 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2717 | collected |
| tor_exit_nodes | 1254 | collected |
| urlhaus_recent_urls | 1313 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3371 |
| cve | 2473 |
| url | 1446 |
| ipv4_cidr | 1124 |
| domain | 869 |
| md5 | 272 |
| sha1 | 272 |
| ipv4 | 173 |
