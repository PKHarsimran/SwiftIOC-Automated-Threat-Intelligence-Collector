# SwiftIOC IOC Summary

_Generated 2026-09-19T18:21:43Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-19T18:21:43Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9502 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 956 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 956 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-19T18:09:26Z |

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
| blocklist_de_ssh | 12162 |
| ipsum_level5 | 6371 |
| greensnow_blocklist | 5114 |
| binarydefense_banlist | 4792 |
| nist_nvd_recent | 2465 |
| cisa_kev | 1716 |
| spamhaus_drop | 1713 |
| malwarebazaar_recent | 1566 |
| tor_exit_nodes | 1356 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3800 |
| sha256 | 2886 |
| ipv4_cidr | 1712 |
| url | 553 |
| domain | 447 |
| ipv4 | 292 |
| sha1 | 259 |
| md5 | 51 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3800 |
| malware | 3441 |
| nvd | 2337 |
| threatfox | 1723 |
| exploited-in-the-wild | 1716 |
| drop | 1712 |
| spamhaus | 1712 |
| high | 791 |
| Mirai | 600 |
| medium | 564 |

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
