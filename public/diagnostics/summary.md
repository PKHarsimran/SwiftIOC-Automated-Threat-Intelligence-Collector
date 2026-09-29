# SwiftIOC IOC Summary

_Generated 2026-09-29T17:30:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-29T17:30:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5630 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1346 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1346 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-29T17:30:08Z |

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
| blocklist_de_ssh | 5413 |
| greensnow_blocklist | 4927 |
| ipsum_level5 | 4242 |
| threatfox_export_json | 2637 |
| nist_nvd_recent | 1989 |
| cisa_kev | 1729 |
| spamhaus_drop | 1694 |
| tor_exit_nodes | 1396 |
| malwarebazaar_recent | 1135 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3271 |
| cve | 3133 |
| ipv4_cidr | 1693 |
| url | 856 |
| domain | 559 |
| sha1 | 231 |
| ipv4 | 214 |
| md5 | 43 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3755 |
| cve | 3133 |
| threatfox | 2447 |
| exploited-in-the-wild | 1729 |
| drop | 1693 |
| spamhaus | 1693 |
| nvd | 1691 |
| Mirai | 1490 |
| malware_download | 667 |
| high | 561 |

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
