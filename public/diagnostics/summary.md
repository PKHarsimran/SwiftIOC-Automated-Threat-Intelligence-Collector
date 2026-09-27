# SwiftIOC IOC Summary

_Generated 2026-09-27T22:46:07Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-27T22:46:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8617 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 1278 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1278 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-27T22:45:49Z |

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
| blocklist_de_ssh | 11744 |
| binarydefense_banlist | 6344 |
| threatfox_export_json | 5216 |
| ipsum_level5 | 5109 |
| greensnow_blocklist | 4492 |
| cisa_kev | 1728 |
| spamhaus_drop | 1711 |
| tor_exit_nodes | 1355 |
| nist_nvd_recent | 1270 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3176 |
| sha256 | 2316 |
| ipv4_cidr | 1710 |
| domain | 1481 |
| url | 893 |
| sha1 | 223 |
| ipv4 | 161 |
| ja3 | 25 |
| md5 | 15 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3176 |
| threatfox | 3057 |
| malware | 2989 |
| nvd | 1734 |
| exploited-in-the-wild | 1728 |
| drop | 1710 |
| spamhaus | 1710 |
| Mirai | 1007 |
| etherhiding | 956 |
| high | 653 |

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
