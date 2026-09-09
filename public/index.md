# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-09T18:08:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-09T18:08:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5049 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 535 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 535 |
| Earliest first_seen | 2019-07-15T19:15:16Z |
| Newest first_seen | 2026-09-09T18:07:24Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 3 sources |
| sha256: `00147abaca1263e02190ac12e15ab0db45bf250ef2dae53e945a9d8b40c01598` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5192 |
| greensnow_blocklist | 4412 |
| nist_nvd_recent | 3600 |
| ipsum_level5 | 3325 |
| threatfox_export_json | 2527 |
| binarydefense_banlist | 2428 |
| spamhaus_drop | 1709 |
| cisa_kev | 1699 |
| tor_exit_nodes | 1341 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3917 |
| domain | 1749 |
| ipv4_cidr | 1708 |
| sha256 | 1373 |
| url | 634 |
| ipv4 | 312 |
| sha1 | 247 |
| md5 | 60 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3917 |
| threatfox | 2711 |
| nvd | 2448 |
| malware | 1948 |
| drop | 1708 |
| spamhaus | 1708 |
| exploited-in-the-wild | 1699 |
| etherhiding | 1161 |
| high | 1066 |
| medium | 663 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 68[.]233[.]116[.]124 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
