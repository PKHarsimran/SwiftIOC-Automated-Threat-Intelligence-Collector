# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-18T20:43:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 23977 |
| Carried forward | 1868 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22777 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 72.2 / 88 |
| High-confidence indicators | 7344 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-18T20:43:38Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2601 |
| blocklist_de_ssh | 5456 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3122 |
| ipsum_level5 | 1692 |
| malwarebazaar_recent | 786 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 884 |
| tor_exit_nodes | 1424 |
| urlhaus_recent_urls | 385 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 5697 |
| cve | 1647 |
| domain | 1504 |
| url | 1024 |
| sha256 | 46 |
| md5 | 41 |
| sha1 | 41 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
