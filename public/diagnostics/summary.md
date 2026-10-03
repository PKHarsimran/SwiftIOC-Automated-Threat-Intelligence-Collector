# SwiftIOC IOC Summary

_Generated 2026-10-03T09:36:46Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T09:36:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3385 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-source overlaps | 1475 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1475 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T09:36:29Z |

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
| ipv4: `209[.]126[.]103[.]97` | score 94, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5533 |
| threatfox_export_json | 4669 |
| ipsum_level5 | 3528 |
| nist_nvd_recent | 1799 |
| cisa_kev | 1733 |
| spamhaus_drop | 1693 |
| tor_exit_nodes | 1379 |
| malwarebazaar_recent | 1147 |
| binarydefense_banlist | 1073 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2785 |
| cve | 2455 |
| domain | 1928 |
| ipv4_cidr | 1483 |
| url | 970 |
| ipv4 | 174 |
| sha1 | 149 |
| md5 | 56 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4467 |
| malware | 2734 |
| cve | 2455 |
| exploited-in-the-wild | 1733 |
| drop | 1483 |
| spamhaus | 1483 |
| etherhiding | 1429 |
| Mirai | 1077 |
| nvd | 1030 |
| elf | 1014 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
