# SwiftIOC IOC Summary

_Generated 2026-09-18T15:43:43Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-18T15:43:43Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6882 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 896 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 896 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-18T15:41:55Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5412 |
| binarydefense_banlist | 4595 |
| greensnow_blocklist | 4551 |
| ipsum_level5 | 4517 |
| nist_nvd_recent | 3200 |
| threatfox_export_json | 2671 |
| cisa_kev | 1715 |
| spamhaus_drop | 1713 |
| malwarebazaar_recent | 1352 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3664 |
| sha256 | 2546 |
| ipv4_cidr | 1712 |
| domain | 817 |
| url | 673 |
| ipv4 | 292 |
| sha1 | 252 |
| md5 | 44 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3664 |
| malware | 3177 |
| nvd | 2200 |
| threatfox | 2065 |
| exploited-in-the-wild | 1715 |
| drop | 1712 |
| spamhaus | 1712 |
| high | 1107 |
| Mirai | 499 |
| malware_download | 459 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
