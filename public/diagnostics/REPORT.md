# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-08T20:06:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5437 |
| Carried forward | 2171 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 27392 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-08T20:05:46Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1629 | collected |
| blocklist_de_ssh | 4486 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1769 | collected |
| dshield_block | 20 | collected |
| et_compromised | 511 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2612 | collected |
| ipsum_level5 | 3847 | collected |
| malwarebazaar_recent | 1002 | collected |
| nist_nvd_recent | 2000 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1762 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2588 | collected |
| tor_exit_nodes | 1238 | collected |
| urlhaus_recent_urls | 1792 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2869 |
| sha256 | 2081 |
| url | 2031 |
| ipv4_cidr | 1761 |
| domain | 568 |
| md5 | 266 |
| sha1 | 266 |
| ipv4 | 158 |
