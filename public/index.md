# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-27T09:45:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-27T09:45:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9468 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1257 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1257 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-27T09:35:31Z |

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
| blocklist_de_ssh | 11774 |
| binarydefense_banlist | 6344 |
| threatfox_export_json | 5864 |
| greensnow_blocklist | 5603 |
| ipsum_level5 | 5109 |
| nist_nvd_recent | 2283 |
| cisa_kev | 1726 |
| spamhaus_drop | 1711 |
| tor_exit_nodes | 1374 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2756 |
| sha256 | 2444 |
| domain | 2313 |
| ipv4_cidr | 1226 |
| url | 874 |
| sha1 | 223 |
| ipv4 | 149 |
| md5 | 15 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3905 |
| malware | 3056 |
| cve | 2756 |
| exploited-in-the-wild | 1726 |
| nvd | 1314 |
| etherhiding | 1229 |
| drop | 1226 |
| spamhaus | 1226 |
| Mirai | 1115 |
| ClickFix | 981 |

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
