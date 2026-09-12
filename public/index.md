# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-12T21:54:10Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-12T21:54:10Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5995 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 724 |
| Score (min / avg / max) | 80 / 80.5 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 724 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-12T21:45:23Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 11263 |
| threatfox_export_json | 4577 |
| greensnow_blocklist | 4337 |
| ipsum_level5 | 4059 |
| binarydefense_banlist | 3111 |
| spamhaus_drop | 1723 |
| cisa_kev | 1709 |
| nist_nvd_recent | 1472 |
| tor_exit_nodes | 1328 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3071 |
| cve | 2849 |
| ipv4_cidr | 1722 |
| domain | 1008 |
| url | 536 |
| sha1 | 348 |
| ipv4 | 326 |
| md5 | 140 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4758 |
| cve | 2849 |
| rat | 2376 |
| asyncrat | 2373 |
| drop | 1722 |
| spamhaus | 1722 |
| exploited-in-the-wild | 1709 |
| nvd | 1384 |
| malware | 1123 |
| etherhiding | 523 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 68[.]233[.]116[.]124 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
