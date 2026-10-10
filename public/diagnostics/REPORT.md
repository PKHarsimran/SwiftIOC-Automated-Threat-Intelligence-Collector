# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-10T04:01:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7643 |
| Carried forward | 2436 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 29590 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-10T03:54:11Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 3095 | collected |
| blocklist_de_ssh | 4304 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1739 | collected |
| dshield_block | 20 | collected |
| et_compromised | 600 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 5272 | collected |
| ipsum_level5 | 4798 | collected |
| malwarebazaar_recent | 975 | collected |
| nist_nvd_recent | 1200 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1684 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2831 | collected |
| tor_exit_nodes | 1207 | collected |
| urlhaus_recent_urls | 1670 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2557 |
| url | 2022 |
| sha256 | 1837 |
| ipv4_cidr | 1561 |
| domain | 1273 |
| md5 | 256 |
| sha1 | 255 |
| ipv4 | 239 |
