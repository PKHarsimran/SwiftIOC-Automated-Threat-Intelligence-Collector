# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-21T09:31:57Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-21T09:31:57Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9632 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 1027 |
| Score (min / avg / max) | 79 / 80.6 / 96 |
| High-score indicators (≥80) | 9778 |
| Corroborated (2+ sources) | 1027 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-21T09:20:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5793 |
| blocklist_de_ssh | 5696 |
| greensnow_blocklist | 5690 |
| binarydefense_banlist | 5194 |
| threatfox_export_json | 1909 |
| cisa_kev | 1716 |
| spamhaus_drop | 1712 |
| malwarebazaar_recent | 1610 |
| tor_exit_nodes | 1377 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3413 |
| cve | 3317 |
| ipv4_cidr | 1711 |
| url | 753 |
| domain | 241 |
| sha1 | 236 |
| ipv4 | 204 |
| ja3 | 97 |
| md5 | 28 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4129 |
| cve | 3317 |
| nvd | 1854 |
| exploited-in-the-wild | 1716 |
| drop | 1711 |
| spamhaus | 1711 |
| threatfox | 1484 |
| high | 779 |
| Mirai | 729 |
| malware_download | 612 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
