# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-12T16:31:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4603 |
| Carried forward | 3549 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 26691 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-12T16:30:29Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1001 | collected |
| blocklist_de_ssh | 4476 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1779 | collected |
| dshield_block | 20 | collected |
| et_compromised | 487 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2714 | collected |
| ipsum_level5 | 3708 | collected |
| malwarebazaar_recent | 1120 | collected |
| nist_nvd_recent | 0 | failed |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1756 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2727 | collected |
| tor_exit_nodes | 1258 | collected |
| urlhaus_recent_urls | 1297 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3166 |
| cve | 2307 |
| ipv4_cidr | 1725 |
| url | 1424 |
| domain | 933 |
| ipv4 | 156 |
| md5 | 148 |
| sha1 | 141 |

## Issues

- ⚠️ **nist_nvd_recent**: 503 Server Error: Service Unavailable for url: https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200&lastModStartDate=2026-11-10T16%3A30%3A29.000&lastModEndDate=2026-11-12T16%3A30%3A29.000
- ⚠️ **nist_nvd_recent** returned zero indicators
