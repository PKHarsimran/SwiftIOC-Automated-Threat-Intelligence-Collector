# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-16T09:00:37Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6662 |
| Carried forward | 2525 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 30568 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-16T08:45:42Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 4148 |
| blocklist_de_ssh | 4717 |
| ci_army_list | 15000 |
| cisa_kev | 1710 |
| dshield_block | 20 |
| et_compromised | 588 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 5400 |
| ipsum_level5 | 4117 |
| malwarebazaar_recent | 1356 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| spamhaus_drop | 1725 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 3667 |
| tor_exit_nodes | 1345 |
| urlhaus_recent_urls | 510 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3527 |
| sha256 | 2444 |
| ipv4_cidr | 1613 |
| domain | 1483 |
| url | 524 |
| sha1 | 220 |
| ipv4 | 177 |
| md5 | 12 |

## Issues

- ⚠️ **nist_nvd_recent**: Response ended prematurely
- ⚠️ **nist_nvd_recent** returned zero indicators
