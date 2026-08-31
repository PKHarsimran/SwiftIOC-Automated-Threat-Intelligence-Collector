# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-31T18:39:16Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-31T18:39:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4683 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 246 |
| Score (min / avg / max) | 77 / 79.8 / 96 |
| High-score indicators (≥80) | 6830 |
| Corroborated (2+ sources) | 246 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-31T18:39:04Z |

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
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `87[.]251[.]66[.]91` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 6992 |
| greensnow_blocklist | 4258 |
| ipsum_level5 | 2885 |
| spamhaus_drop | 1708 |
| cisa_kev | 1687 |
| binarydefense_banlist | 1558 |
| tor_exit_nodes | 1427 |
| threatfox_export_json | 823 |
| malwarebazaar_recent | 749 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3566 |
| cve | 3260 |
| ipv4_cidr | 1708 |
| url | 634 |
| domain | 204 |
| ipv4 | 200 |
| md5 | 169 |
| sha1 | 162 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3906 |
| cve | 3260 |
| nvd | 1791 |
| drop | 1708 |
| spamhaus | 1708 |
| exploited-in-the-wild | 1687 |
| Mirai | 1208 |
| threatfox | 1027 |
| high | 856 |
| malware_download | 522 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 106[.]13[.]46[.]38 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 145[.]239[.]85[.]111 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 186[.]209[.]77[.]237 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
