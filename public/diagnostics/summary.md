# SwiftIOC IOC Summary

_Generated 2026-09-07T02:31:53Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-07T02:31:53Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5421 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 256 |
| Score (min / avg / max) | 78 / 80.0 / 96 |
| High-score indicators (≥80) | 7541 |
| Corroborated (2+ sources) | 256 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-07T02:25:02Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `197[.]140[.]9[.]148` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5617 |
| greensnow_blocklist | 4982 |
| ipsum_level5 | 3200 |
| threatfox_export_json | 1953 |
| binarydefense_banlist | 1877 |
| spamhaus_drop | 1709 |
| cisa_kev | 1695 |
| tor_exit_nodes | 1340 |
| et_compromised | 564 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3060 |
| sha256 | 2755 |
| ipv4_cidr | 1708 |
| domain | 1153 |
| url | 465 |
| ipv4 | 316 |
| md5 | 224 |
| sha1 | 222 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3060 |
| malware | 2784 |
| threatfox | 2354 |
| drop | 1708 |
| spamhaus | 1708 |
| exploited-in-the-wild | 1695 |
| nvd | 1590 |
| ClickFix | 862 |
| high | 714 |
| Mirai | 661 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 68[.]233[.]116[.]124 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
