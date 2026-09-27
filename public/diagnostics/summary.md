# SwiftIOC IOC Summary

_Generated 2026-09-27T15:22:11Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-27T15:22:11Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8653 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1267 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1267 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-27T15:22:01Z |

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
| blocklist_de_ssh | 11798 |
| binarydefense_banlist | 6344 |
| threatfox_export_json | 6178 |
| ipsum_level5 | 5109 |
| greensnow_blocklist | 4482 |
| cisa_kev | 1726 |
| spamhaus_drop | 1711 |
| nist_nvd_recent | 1589 |
| tor_exit_nodes | 1358 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2766 |
| domain | 2544 |
| sha256 | 2491 |
| url | 928 |
| ipv4_cidr | 883 |
| sha1 | 223 |
| ipv4 | 150 |
| md5 | 15 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4170 |
| malware | 3134 |
| cve | 2766 |
| exploited-in-the-wild | 1726 |
| etherhiding | 1435 |
| nvd | 1324 |
| Mirai | 1100 |
| ClickFix | 1016 |
| drop | 883 |
| spamhaus | 883 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
