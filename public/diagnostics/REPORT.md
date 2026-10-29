# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-29T04:06:32Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8709 |
| Carried forward | 413 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 31802 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-29T04:01:44Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 430 | collected |
| blocklist_de_ssh | 5047 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1762 | collected |
| dshield_block | 20 | collected |
| et_compromised | 524 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4945 | collected |
| ipsum_level5 | 5728 | collected |
| malwarebazaar_recent | 1660 | collected |
| nist_nvd_recent | 2400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1760 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 3883 | collected |
| tor_exit_nodes | 1230 | collected |
| urlhaus_recent_urls | 5307 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 4937 |
| cve | 1806 |
| ipv4_cidr | 1243 |
| sha256 | 1232 |
| domain | 501 |
| ipv4 | 122 |
| sha1 | 80 |
| md5 | 79 |
