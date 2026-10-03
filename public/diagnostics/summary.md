# SwiftIOC IOC Summary

_Generated 2026-10-03T18:57:11Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-03T18:57:11Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2884 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-source overlaps | 1464 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1464 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-03T18:56:57Z |

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
| ipv4: `209[.]126[.]103[.]97` | score 90, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 4879 |
| greensnow_blocklist | 4614 |
| ipsum_level5 | 3528 |
| cisa_kev | 1733 |
| spamhaus_drop | 1693 |
| nist_nvd_recent | 1667 |
| tor_exit_nodes | 1396 |
| binarydefense_banlist | 1073 |
| malwarebazaar_recent | 945 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3046 |
| cve | 2281 |
| domain | 1900 |
| ipv4_cidr | 1400 |
| url | 1030 |
| ipv4 | 174 |
| sha1 | 131 |
| md5 | 38 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4711 |
| malware | 2737 |
| cve | 2281 |
| exploited-in-the-wild | 1733 |
| elf | 1434 |
| Mirai | 1431 |
| etherhiding | 1415 |
| drop | 1400 |
| spamhaus | 1400 |
| ClickFix | 1028 |

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
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
