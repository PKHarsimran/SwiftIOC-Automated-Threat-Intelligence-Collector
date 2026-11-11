# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-11T04:22:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5162 |
| Carried forward | 2265 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27806 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-11T04:09:14Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 653 | collected |
| blocklist_de_ssh | 4421 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1779 | collected |
| dshield_block | 20 | collected |
| et_compromised | 491 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3431 | collected |
| ipsum_level5 | 3423 | collected |
| malwarebazaar_recent | 2105 | collected |
| nist_nvd_recent | 2800 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1764 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2073 | collected |
| tor_exit_nodes | 1254 | collected |
| urlhaus_recent_urls | 1087 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3161 |
| cve | 2793 |
| ipv4_cidr | 1763 |
| url | 1249 |
| domain | 473 |
| md5 | 200 |
| sha1 | 200 |
| ipv4 | 161 |
