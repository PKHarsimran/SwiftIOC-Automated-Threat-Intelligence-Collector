# SwiftIOC IOC Summary

_Generated 2026-09-03T02:40:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-03T02:40:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5136 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 253 |
| Score (min / avg / max) | 77 / 79.8 / 96 |
| High-score indicators (≥80) | 6834 |
| Corroborated (2+ sources) | 253 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-03T02:22:07Z |

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
| blocklist_de_ssh | 11627 |
| greensnow_blocklist | 5254 |
| ipsum_level5 | 3111 |
| spamhaus_drop | 1707 |
| cisa_kev | 1694 |
| tor_exit_nodes | 1413 |
| threatfox_export_json | 1076 |
| malwarebazaar_recent | 798 |
| urlhaus_recent_urls | 761 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3147 |
| cve | 3102 |
| ipv4_cidr | 1709 |
| url | 995 |
| ipv4 | 298 |
| domain | 237 |
| md5 | 211 |
| sha1 | 204 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3800 |
| cve | 3102 |
| drop | 1709 |
| spamhaus | 1709 |
| exploited-in-the-wild | 1694 |
| nvd | 1629 |
| threatfox | 1292 |
| Mirai | 982 |
| malware_download | 895 |
| high | 779 |

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
