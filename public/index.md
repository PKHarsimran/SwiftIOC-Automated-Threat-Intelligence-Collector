# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-30T23:23:59Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-30T23:23:59Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6145 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1360 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1360 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-30T23:16:22Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `45[.]198[.]224[.]184` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5754 |
| blocklist_de_ssh | 5249 |
| ipsum_level5 | 4277 |
| nist_nvd_recent | 2800 |
| threatfox_export_json | 2012 |
| cisa_kev | 1730 |
| spamhaus_drop | 1693 |
| tor_exit_nodes | 1405 |
| malwarebazaar_recent | 1284 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3214 |
| cve | 3054 |
| ipv4_cidr | 1587 |
| url | 895 |
| domain | 653 |
| ipv4 | 365 |
| sha1 | 182 |
| md5 | 50 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3602 |
| cve | 3054 |
| threatfox | 2791 |
| exploited-in-the-wild | 1730 |
| nvd | 1622 |
| drop | 1587 |
| spamhaus | 1587 |
| Mirai | 1301 |
| malware_download | 670 |
| high | 537 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
