# SwiftIOC IOC Summary

_Generated 2026-09-03T19:02:43Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-03T19:02:43Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4444 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 251 |
| Score (min / avg / max) | 77 / 79.9 / 96 |
| High-score indicators (≥80) | 6931 |
| Corroborated (2+ sources) | 251 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-03T18:49:18Z |

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
| blocklist_de_ssh | 11304 |
| greensnow_blocklist | 4552 |
| ipsum_level5 | 3111 |
| spamhaus_drop | 1710 |
| cisa_kev | 1694 |
| tor_exit_nodes | 1400 |
| threatfox_export_json | 1322 |
| binarydefense_banlist | 715 |
| malwarebazaar_recent | 699 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3133 |
| sha256 | 2900 |
| ipv4_cidr | 1709 |
| url | 992 |
| domain | 534 |
| ipv4 | 250 |
| md5 | 193 |
| sha1 | 192 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3507 |
| cve | 3133 |
| drop | 1709 |
| spamhaus | 1709 |
| exploited-in-the-wild | 1694 |
| nvd | 1660 |
| threatfox | 1552 |
| Mirai | 893 |
| malware_download | 831 |
| high | 762 |

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
