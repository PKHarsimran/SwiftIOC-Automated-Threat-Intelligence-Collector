# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-04T02:36:41Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-04T02:36:41Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4787 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 254 |
| Score (min / avg / max) | 76 / 79.8 / 96 |
| High-score indicators (≥80) | 6893 |
| Corroborated (2+ sources) | 254 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-04T02:36:08Z |

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
| blocklist_de_ssh | 11254 |
| greensnow_blocklist | 5269 |
| ipsum_level5 | 2667 |
| spamhaus_drop | 1710 |
| cisa_kev | 1694 |
| tor_exit_nodes | 1396 |
| threatfox_export_json | 1311 |
| binarydefense_banlist | 1038 |
| malwarebazaar_recent | 692 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3138 |
| sha256 | 2957 |
| ipv4_cidr | 1709 |
| url | 841 |
| domain | 576 |
| ipv4 | 243 |
| md5 | 220 |
| sha1 | 219 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3386 |
| cve | 3138 |
| drop | 1709 |
| spamhaus | 1709 |
| exploited-in-the-wild | 1694 |
| threatfox | 1665 |
| nvd | 1665 |
| Mirai | 889 |
| high | 767 |
| malware_download | 682 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 3[.]131[.]220[.]121 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 92[.]5[.]132[.]170 | binarydefense_banlist, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 95[.]173[.]161[.]147 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
