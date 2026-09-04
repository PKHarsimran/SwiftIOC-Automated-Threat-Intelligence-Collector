# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-04T22:02:20Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-04T22:02:20Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4421 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 251 |
| Score (min / avg / max) | 78 / 79.8 / 96 |
| High-score indicators (≥80) | 6583 |
| Corroborated (2+ sources) | 251 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-04T21:54:40Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `197[.]140[.]9[.]148` | score 96, 4 sources |
| ipv4: `206[.]42[.]5[.]12` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 11116 |
| greensnow_blocklist | 4472 |
| ipsum_level5 | 2667 |
| spamhaus_drop | 1709 |
| cisa_kev | 1695 |
| tor_exit_nodes | 1339 |
| binarydefense_banlist | 1038 |
| threatfox_export_json | 908 |
| malwarebazaar_recent | 763 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3094 |
| sha256 | 3081 |
| ipv4_cidr | 1710 |
| url | 809 |
| domain | 576 |
| ipv4 | 258 |
| md5 | 188 |
| sha1 | 187 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3528 |
| cve | 3094 |
| drop | 1710 |
| spamhaus | 1710 |
| exploited-in-the-wild | 1695 |
| nvd | 1621 |
| threatfox | 1571 |
| Mirai | 884 |
| high | 739 |
| malware_download | 668 |

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
