# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-10T16:50:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7038 |
| Carried forward | 2954 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 29548 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-10T16:40:39Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 3095 | collected |
| blocklist_de_ssh | 4309 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1739 | collected |
| dshield_block | 20 | collected |
| et_compromised | 600 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 4294 | collected |
| ipsum_level5 | 4798 | collected |
| malwarebazaar_recent | 919 | collected |
| nist_nvd_recent | 2400 | collected |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1684 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2453 | collected |
| tor_exit_nodes | 1203 | collected |
| urlhaus_recent_urls | 716 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3763 |
| sha256 | 1883 |
| ipv4_cidr | 1683 |
| url | 1051 |
| domain | 1042 |
| ipv4 | 241 |
| md5 | 169 |
| sha1 | 168 |
