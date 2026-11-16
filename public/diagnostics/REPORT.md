# SwiftIOC Run Report

## Overview

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-16T04:28:12Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2944 |
| Carried forward | 2972 |
| Expired (score < 20) | 0 |
| Aged out (> 30d) | 0 |
| Pruned over cap (10000) | 24248 |
| Stored | 10000 |
| Score (min / avg / max) | 79 / 80.4 / 96 |
| High-confidence indicators | 9930 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-16T04:19:57Z |

## Per-source coverage

Collected means records returned in the configured window, not a guarantee of complete upstream coverage.

| Source | Indicators | State |
| --- | ---: | --- |
| binarydefense_banlist | 1099 | collected |
| blocklist_de_ssh | 4658 | collected |
| ci_army_list | 15000 | collected |
| cisa_kev | 1781 | collected |
| dshield_block | 20 | collected |
| et_compromised | 584 | collected |
| feodo_ipblocklist | 5 | collected |
| greensnow_blocklist | 0 | failed |
| ipsum_level5 | 2773 | collected |
| malwarebazaar_recent | 1138 | collected |
| nist_nvd_recent | 0 | failed |
| openphish_feed | 300 | collected |
| spamhaus_drop | 1759 | collected |
| sslbl_ja3 | 0 | failed |
| threatfox_export_json | 2665 | collected |
| tor_exit_nodes | 1260 | collected |
| urlhaus_recent_urls | 1178 | collected |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2978 |
| sha256 | 2214 |
| ipv4_cidr | 1758 |
| url | 1388 |
| domain | 913 |
| md5 | 285 |
| sha1 | 285 |
| ipv4 | 179 |

## Issues

- ⚠️ **nist_nvd_recent**: 503 Server Error: Service Unavailable for url: https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200&lastModStartDate=2026-11-14T04%3A26%3A43.000&lastModEndDate=2026-11-16T04%3A26%3A43.000
- ⚠️ **sslbl_ja3**: HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Max retries exceeded with url: /blacklist/ja3_fingerprints.csv (Caused by ReadTimeoutError("HTTPSConnectionPool(host='sslbl.abuse.ch', port=443): Read timed out. (read timeout=20)"))
- ⚠️ **greensnow_blocklist**: 503 Server Error: Service Unavailable for url: https://blocklist.greensnow.co/greensnow.txt
- ⚠️ **greensnow_blocklist** returned zero indicators
- ⚠️ **nist_nvd_recent** returned zero indicators
- ⚠️ **sslbl_ja3** returned zero indicators
