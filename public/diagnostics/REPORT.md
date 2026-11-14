# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-14T23:35:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4076 |
| Carried forward | 3156 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 25437 |
| Stored | 10000 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-confidence indicators | 10000 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-14T23:26:00Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 324 | collected |
| blocklist_de_ssh | 4838 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1781 | collected |
| dshield_block | 20 | collected |
| et_compromised | 584 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 2712 | collected |
| ipsum_level5 | 3322 | collected |
| malwarebazaar_recent | 1184 | collected |
| nist_nvd_recent | 0 | failed |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1759 | collected |
| sslbl_ja3 | 97 | collected |
| threatfox_export_json | 2352 | collected |
| tor_exit_nodes | 1259 | collected |
| urlhaus_recent_urls | 820 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3122 |
| sha256 | 2558 |
| ipv4_cidr | 1758 |
| domain | 940 |
| url | 927 |
| md5 | 222 |
| sha1 | 215 |
| ipv4 | 169 |
| ja3 | 89 |

## Issues

- ⚠️ **nist_nvd_recent**: 503 Server Error: Service Unavailable for url: https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200&lastModStartDate=2026-11-12T23%3A35%3A02.000&lastModEndDate=2026-11-14T23%3A35%3A02.000
- ⚠️ **nist_nvd_recent** returned zero indicators
