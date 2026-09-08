# SwiftIOC IOC Summary

_Generated 2026-09-08T22:18:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-08T22:18:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4987 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 518 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 518 |
| Earliest first_seen | 2019-07-15T19:15:16Z |
| Newest first_seen | 2026-09-08T22:18:29Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 3 sources |
| ipv4: `197[.]140[.]9[.]148` | score 89, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5414 |
| greensnow_blocklist | 4311 |
| ipsum_level5 | 3666 |
| nist_nvd_recent | 3400 |
| threatfox_export_json | 2558 |
| binarydefense_banlist | 2145 |
| spamhaus_drop | 1707 |
| cisa_kev | 1699 |
| tor_exit_nodes | 1339 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4158 |
| domain | 1699 |
| sha256 | 1343 |
| ipv4_cidr | 865 |
| sha1 | 861 |
| url | 626 |
| ipv4 | 332 |
| md5 | 116 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4158 |
| threatfox | 2856 |
| nvd | 2688 |
| malware | 2390 |
| exploited-in-the-wild | 1699 |
| high | 1239 |
| etherhiding | 1161 |
| drop | 865 |
| spamhaus | 865 |
| medium | 799 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 68[.]233[.]116[.]124 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
