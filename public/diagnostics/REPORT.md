# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-18T06:04:10Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 25729 |
| Carried forward | 467 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 22744 |
| Stored | 10000 |
| Score (min / avg / max) | 60 / 71.9 / 88 |
| High-confidence indicators | 8091 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-18T06:03:34Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 2601 |
| blocklist_de_ssh | 5354 |
| ci_army_list | 15000 |
| cisa_kev | 1647 |
| et_compromised | 578 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 3967 |
| ipsum_level5 | 1692 |
| malwarebazaar_recent | 875 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 1831 |
| tor_exit_nodes | 1422 |
| urlhaus_recent_urls | 360 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 6573 |
| cve | 1647 |
| domain | 1388 |
| url | 330 |
| sha256 | 24 |
| md5 | 19 |
| sha1 | 19 |

## Issues

- ⚠️ **nist_nvd_recent** returned zero indicators
