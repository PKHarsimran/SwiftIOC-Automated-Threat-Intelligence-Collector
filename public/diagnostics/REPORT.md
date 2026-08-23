# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-23T01:00:56Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2299 |
| Carried forward | 3761 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 24339 |
| Stored | 10000 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-confidence indicators | 7275 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-23T01:00:46Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2918 |
| blocklist_de_ssh | 5274 |
| ci_army_list | 15000 |
| cisa_kev | 1674 |
| dshield_block | 20 |
| et_compromised | 544 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 0 |
| ipsum_level5 | 1413 |
| malwarebazaar_recent | 760 |
| nist_nvd_recent | 200 |
| openphish_feed | 300 |
| spamhaus_drop | 1699 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1287 |
| tor_exit_nodes | 1372 |
| urlhaus_recent_urls | 314 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3377 |
| cve | 2452 |
| ipv4_cidr | 1698 |
| ipv4 | 867 |
| domain | 644 |
| url | 504 |
| md5 | 184 |
| sha1 | 177 |
| ja3 | 97 |

## Issues

- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
