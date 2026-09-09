# SwiftIOC IOC Summary

_Generated 2026-09-09T08:36:34Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-09T08:36:34Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5425 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 519 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 519 |
| Earliest first_seen | 2019-07-15T19:15:16Z |
| Newest first_seen | 2026-09-09T08:33:07Z |

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
| blocklist_de_ssh | 5395 |
| greensnow_blocklist | 5153 |
| nist_nvd_recent | 4108 |
| ipsum_level5 | 3325 |
| threatfox_export_json | 2478 |
| binarydefense_banlist | 2428 |
| spamhaus_drop | 1707 |
| cisa_kev | 1699 |
| tor_exit_nodes | 1341 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4097 |
| domain | 1708 |
| ipv4_cidr | 1699 |
| sha256 | 1294 |
| url | 609 |
| ipv4 | 310 |
| sha1 | 229 |
| md5 | 54 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4097 |
| threatfox | 2655 |
| nvd | 2628 |
| malware | 1818 |
| exploited-in-the-wild | 1699 |
| drop | 1699 |
| spamhaus | 1699 |
| etherhiding | 1161 |
| high | 1105 |
| medium | 744 |

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
