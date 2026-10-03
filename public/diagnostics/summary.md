# SwiftIOC IOC Summary

_Generated 2026-10-03T22:37:16Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T22:37:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2833 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-source overlaps | 1463 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1463 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T22:37:07Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `45[.]198[.]224[.]184` | score 96, 4 sources |
| ipv4: `45[.]78[.]201[.]248` | score 96, 4 sources |
| ipv4: `209[.]126[.]103[.]97` | score 89, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 4565 |
| greensnow_blocklist | 4539 |
| ipsum_level5 | 3528 |
| cisa_kev | 1733 |
| spamhaus_drop | 1692 |
| nist_nvd_recent | 1506 |
| tor_exit_nodes | 1401 |
| binarydefense_banlist | 1073 |
| malwarebazaar_recent | 917 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3174 |
| cve | 2244 |
| ipv4_cidr | 1651 |
| domain | 1488 |
| url | 1081 |
| ipv4 | 193 |
| sha1 | 131 |
| md5 | 38 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4426 |
| malware | 2808 |
| cve | 2244 |
| exploited-in-the-wild | 1733 |
| drop | 1651 |
| spamhaus | 1651 |
| elf | 1556 |
| Mirai | 1526 |
| etherhiding | 1009 |
| malware_download | 851 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]148[.]49 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
