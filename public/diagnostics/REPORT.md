# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-17T20:51:29Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 24607 |
| Carried forward | 407 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22019 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 70.5 / 88 |
| High-confidence indicators | 7196 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-07-17T20:51:18Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2373 |
| blocklist_de_ssh | 5351 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3471 |
| ipsum_level5 | 1578 |
| malwarebazaar_recent | 901 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1581 |
| tor_exit_nodes | 1422 |
| urlhaus_recent_urls | 303 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 6258 |
| cve | 1647 |
| domain | 1291 |
| url | 729 |
| ja3 | 49 |
| sha256 | 12 |
| md5 | 7 |
| sha1 | 7 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
