# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-02T04:01:14Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7228 |
| Carried forward | 1247 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25828 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-02T03:59:59Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1052 | collected |
| blocklist_de_ssh | 5128 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1766 | collected |
| dshield_block | 20 | collected |
| et_compromised | 542 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 3912 | collected |
| ipsum_level5 | 4418 | collected |
| malwarebazaar_recent | 935 | collected |
| nist_nvd_recent | 419 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1754 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3668 | collected |
| tor_exit_nodes | 1237 | collected |
| urlhaus_recent_urls | 1556 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2515 |
| url | 1925 |
| sha256 | 1848 |
| ipv4_cidr | 1753 |
| domain | 1352 |
| ipv4 | 287 |
| md5 | 160 |
| sha1 | 160 |
