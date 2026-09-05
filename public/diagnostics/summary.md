# SwiftIOC IOC Summary

_Generated 2026-09-05T02:37:01Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-05T02:37:01Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5322 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 400 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 6519 |
| Corroborated (2+ sources) | 400 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-05T02:36:50Z |

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
| blocklist_de_ssh | 11094 |
| greensnow_blocklist | 5295 |
| ipsum_level5 | 3353 |
| spamhaus_drop | 1709 |
| cisa_kev | 1695 |
| tor_exit_nodes | 1339 |
| binarydefense_banlist | 1325 |
| threatfox_export_json | 922 |
| malwarebazaar_recent | 745 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3110 |
| cve | 3096 |
| ipv4_cidr | 1710 |
| url | 597 |
| domain | 591 |
| ipv4 | 424 |
| md5 | 188 |
| sha1 | 187 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3349 |
| cve | 3096 |
| drop | 1710 |
| spamhaus | 1710 |
| exploited-in-the-wild | 1695 |
| nvd | 1623 |
| threatfox | 1599 |
| Mirai | 896 |
| high | 739 |
| medium | 520 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 107[.]150[.]97[.]10 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 192[.]227[.]221[.]227 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 2[.]57[.]121[.]112 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 2[.]57[.]122[.]53 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 31[.]58[.]216[.]82 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 85[.]217[.]149[.]70 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 104[.]236[.]19[.]165 | blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
