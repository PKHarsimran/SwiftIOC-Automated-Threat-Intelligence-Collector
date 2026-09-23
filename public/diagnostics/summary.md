# SwiftIOC IOC Summary

_Generated 2026-09-23T03:00:07Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-23T03:00:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9113 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1114 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1114 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-23T02:54:53Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `176[.]65[.]139[.]206` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5944 |
| binarydefense_banlist | 5581 |
| blocklist_de_ssh | 5561 |
| ipsum_level5 | 4822 |
| nist_nvd_recent | 2000 |
| cisa_kev | 1721 |
| threatfox_export_json | 1720 |
| spamhaus_drop | 1712 |
| tor_exit_nodes | 1379 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3147 |
| cve | 2617 |
| ipv4_cidr | 1711 |
| url | 1226 |
| domain | 722 |
| sha1 | 265 |
| ipv4 | 255 |
| md5 | 57 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4118 |
| cve | 2617 |
| threatfox | 2375 |
| exploited-in-the-wild | 1721 |
| drop | 1711 |
| spamhaus | 1711 |
| nvd | 1158 |
| malware_download | 918 |
| Mirai | 692 |
| mirai | 448 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
