# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-08T19:13:01Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-08T19:13:01Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5005 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 518 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 518 |
| Earliest first_seen | 2019-07-15T19:15:16Z |
| Newest first_seen | 2026-09-08T19:05:08Z |

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
| ipv4: `197[.]140[.]9[.]148` | score 90, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5413 |
| greensnow_blocklist | 4339 |
| ipsum_level5 | 3666 |
| threatfox_export_json | 2560 |
| nist_nvd_recent | 2370 |
| binarydefense_banlist | 2145 |
| spamhaus_drop | 1707 |
| cisa_kev | 1699 |
| tor_exit_nodes | 1346 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3844 |
| domain | 1718 |
| sha256 | 1307 |
| url | 962 |
| ipv4_cidr | 873 |
| sha1 | 861 |
| ipv4 | 319 |
| md5 | 116 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3844 |
| threatfox | 2864 |
| malware | 2688 |
| nvd | 2374 |
| exploited-in-the-wild | 1699 |
| etherhiding | 1161 |
| high | 1147 |
| drop | 873 |
| spamhaus | 873 |
| medium | 701 |

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
