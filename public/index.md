# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-21T02:59:17Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-21T02:59:17Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 10007 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 1011 |
| Score (min / avg / max) | 79 / 80.6 / 96 |
| High-score indicators (≥80) | 9823 |
| Corroborated (2+ sources) | 1011 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-21T02:50:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 12008 |
| ipsum_level5 | 5793 |
| greensnow_blocklist | 5637 |
| binarydefense_banlist | 5194 |
| threatfox_export_json | 1824 |
| cisa_kev | 1716 |
| spamhaus_drop | 1712 |
| malwarebazaar_recent | 1640 |
| tor_exit_nodes | 1374 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3514 |
| sha256 | 3318 |
| ipv4_cidr | 1711 |
| url | 613 |
| sha1 | 259 |
| domain | 224 |
| ipv4 | 213 |
| ja3 | 97 |
| md5 | 51 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3971 |
| cve | 3514 |
| nvd | 2051 |
| exploited-in-the-wild | 1716 |
| drop | 1711 |
| spamhaus | 1711 |
| threatfox | 1432 |
| high | 790 |
| Mirai | 626 |
| medium | 580 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
