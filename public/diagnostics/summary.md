# SwiftIOC IOC Summary

_Generated 2026-09-05T11:46:36Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-05T11:46:36Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4799 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 254 |
| Score (min / avg / max) | 77 / 79.8 / 96 |
| High-score indicators (≥80) | 6537 |
| Corroborated (2+ sources) | 254 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-05T11:39:11Z |

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
| blocklist_de_ssh | 11244 |
| greensnow_blocklist | 4296 |
| ipsum_level5 | 3353 |
| spamhaus_drop | 1709 |
| cisa_kev | 1695 |
| tor_exit_nodes | 1341 |
| binarydefense_banlist | 1325 |
| threatfox_export_json | 909 |
| malwarebazaar_recent | 741 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3221 |
| cve | 3116 |
| ipv4_cidr | 1710 |
| url | 741 |
| domain | 417 |
| ipv4 | 323 |
| md5 | 188 |
| sha1 | 187 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3554 |
| cve | 3116 |
| drop | 1710 |
| spamhaus | 1710 |
| exploited-in-the-wild | 1695 |
| nvd | 1645 |
| threatfox | 1523 |
| Mirai | 945 |
| high | 751 |
| malware_download | 576 |

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
