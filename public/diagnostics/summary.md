# SwiftIOC IOC Summary

_Generated 2026-10-04T10:27:12Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-04T10:27:12Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2820 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-source overlaps | 1404 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1404 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-04T10:26:58Z |

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
| sha256: `0345370e70311cfab06adb18c67785c3f8377f35a66b54d0619d620434165373` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 4760 |
| ipsum_level5 | 3731 |
| greensnow_blocklist | 3128 |
| cisa_kev | 1733 |
| spamhaus_drop | 1692 |
| tor_exit_nodes | 1398 |
| binarydefense_banlist | 1397 |
| nist_nvd_recent | 1336 |
| malwarebazaar_recent | 1044 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3967 |
| cve | 2261 |
| domain | 1309 |
| url | 1198 |
| ipv4_cidr | 957 |
| ipv4 | 201 |
| sha1 | 69 |
| md5 | 38 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4706 |
| malware | 3146 |
| cve | 2261 |
| Mirai | 2108 |
| elf | 2058 |
| exploited-in-the-wild | 1733 |
| malware_download | 985 |
| etherhiding | 978 |
| drop | 957 |
| spamhaus | 957 |

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
