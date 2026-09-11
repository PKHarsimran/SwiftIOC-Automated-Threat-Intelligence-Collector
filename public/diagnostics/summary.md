# SwiftIOC IOC Summary

_Generated 2026-09-11T15:46:09Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-11T15:46:09Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5922 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 654 |
| Score (min / avg / max) | 80 / 80.5 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 654 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-11T15:44:30Z |

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
| ipv4: `94[.]154[.]43[.]69` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 6016 |
| blocklist_de_ssh | 5296 |
| greensnow_blocklist | 4545 |
| ipsum_level5 | 4011 |
| binarydefense_banlist | 2896 |
| nist_nvd_recent | 2600 |
| spamhaus_drop | 1723 |
| cisa_kev | 1705 |
| tor_exit_nodes | 1336 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4056 |
| cve | 2037 |
| ipv4_cidr | 1722 |
| domain | 1253 |
| url | 362 |
| sha1 | 290 |
| ipv4 | 198 |
| md5 | 82 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 5452 |
| rat | 3294 |
| asyncrat | 3293 |
| cve | 2037 |
| drop | 1722 |
| spamhaus | 1722 |
| exploited-in-the-wild | 1705 |
| malware | 1181 |
| etherhiding | 895 |
| Polygon | 631 |

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
