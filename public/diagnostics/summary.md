# SwiftIOC IOC Summary

_Generated 2026-09-07T22:28:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-07T22:28:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4847 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 496 |
| Score (min / avg / max) | 79 / 80.3 / 96 |
| High-score indicators (≥80) | 9366 |
| Corroborated (2+ sources) | 496 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-07T22:17:22Z |

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
| blocklist_de_ssh | 5626 |
| greensnow_blocklist | 4384 |
| ipsum_level5 | 3200 |
| threatfox_export_json | 2211 |
| binarydefense_banlist | 1877 |
| spamhaus_drop | 1708 |
| cisa_kev | 1695 |
| tor_exit_nodes | 1341 |
| malwarebazaar_recent | 825 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2681 |
| sha1 | 1816 |
| ipv4_cidr | 1707 |
| domain | 1455 |
| sha256 | 1064 |
| url | 710 |
| ipv4 | 333 |
| md5 | 137 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3205 |
| cve | 2681 |
| threatfox | 2553 |
| drop | 1707 |
| spamhaus | 1707 |
| exploited-in-the-wild | 1695 |
| nvd | 1211 |
| ClickFix | 1019 |
| Mirai | 701 |
| malware_download | 510 |

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
