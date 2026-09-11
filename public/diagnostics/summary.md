# SwiftIOC IOC Summary

_Generated 2026-09-11T18:56:10Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-11T18:56:10Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5904 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 658 |
| Score (min / avg / max) | 80 / 80.5 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 658 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-11T18:42:23Z |

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
| threatfox_export_json | 6367 |
| blocklist_de_ssh | 5296 |
| greensnow_blocklist | 4678 |
| ipsum_level5 | 4011 |
| nist_nvd_recent | 3197 |
| binarydefense_banlist | 2896 |
| spamhaus_drop | 1723 |
| cisa_kev | 1708 |
| tor_exit_nodes | 1341 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3677 |
| cve | 2117 |
| ipv4_cidr | 1722 |
| domain | 1507 |
| url | 424 |
| sha1 | 290 |
| ipv4 | 181 |
| md5 | 82 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 5559 |
| rat | 3080 |
| asyncrat | 3078 |
| cve | 2117 |
| drop | 1722 |
| spamhaus | 1722 |
| exploited-in-the-wild | 1708 |
| malware | 994 |
| etherhiding | 895 |
| nvd | 652 |

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
