# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-22T02:08:59Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4573 |
| Carried forward | 1557 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25578 |
| Stored | 10000 |
| Score (min / avg / max) | 68 / 77.8 / 96 |
| High-confidence indicators | 9115 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-22T02:08:35Z |

## Per-source counts

| Source | Indicators |
| --- | ---: |
| binarydefense_banlist | 3507 |
| blocklist_de_ssh | 5866 |
| ci_army_list | 15000 |
| cisa_kev | 1651 |
| dshield_block | 20 |
| et_compromised | 590 |
| feodo_ipblocklist | 5 |
| greensnow_blocklist | 4067 |
| ipsum_level5 | 2325 |
| malwarebazaar_recent | 743 |
| nist_nvd_recent | 0 |
| openphish_feed | 300 |
| spamhaus_drop | 1669 |
| sslbl_ja3 | 97 |
| threatfox_export_json | 997 |
| tor_exit_nodes | 1421 |
| urlhaus_recent_urls | 336 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 3527 |
| cve | 2295 |
| ipv4_cidr | 1682 |
| domain | 905 |
| sha256 | 840 |
| url | 502 |
| ja3 | 97 |
| md5 | 76 |
| sha1 | 76 |

## Issues

- ⚠️ **nist_nvd_recent**: 503 Server Error: Service Unavailable for url: https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200&lastModStartDate=2026-07-20T02%3A08%3A31.000&lastModEndDate=2026-07-22T02%3A08%3A31.000
- ⚠️ **nist_nvd_recent** returned zero indicators
