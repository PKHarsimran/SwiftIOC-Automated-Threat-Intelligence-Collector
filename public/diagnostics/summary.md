# SwiftIOC IOC Summary

_Generated 2026-09-11T08:30:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-11T08:30:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6396 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 648 |
| Score (min / avg / max) | 80 / 80.5 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 648 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-11T08:19:29Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |
| sha256: `0298b368f84837c39e3361517e0efc6ff0e1e25e17cdd34cfd297f15f4a149ff` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 6138 |
| greensnow_blocklist | 5319 |
| blocklist_de_ssh | 5225 |
| ipsum_level5 | 4011 |
| binarydefense_banlist | 2896 |
| nist_nvd_recent | 2600 |
| spamhaus_drop | 1711 |
| cisa_kev | 1705 |
| tor_exit_nodes | 1335 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4103 |
| cve | 2101 |
| ipv4_cidr | 1710 |
| domain | 1208 |
| url | 311 |
| sha1 | 294 |
| ipv4 | 186 |
| md5 | 87 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 5395 |
| rat | 3295 |
| asyncrat | 3293 |
| cve | 2101 |
| drop | 1710 |
| spamhaus | 1710 |
| exploited-in-the-wild | 1705 |
| malware | 1180 |
| etherhiding | 867 |
| nvd | 636 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 68[.]233[.]116[.]124 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
