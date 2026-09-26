# SwiftIOC IOC Summary

_Generated 2026-09-26T15:37:24Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-26T15:37:24Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8543 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1226 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1226 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-26T15:36:58Z |

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
| binarydefense_banlist | 6160 |
| blocklist_de_ssh | 5034 |
| greensnow_blocklist | 4872 |
| ipsum_level5 | 4856 |
| nist_nvd_recent | 3600 |
| threatfox_export_json | 2487 |
| cisa_kev | 1726 |
| spamhaus_drop | 1711 |
| malwarebazaar_recent | 1464 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3094 |
| sha256 | 2297 |
| domain | 1727 |
| ipv4_cidr | 1710 |
| url | 746 |
| sha1 | 228 |
| ipv4 | 178 |
| md5 | 20 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3241 |
| cve | 3094 |
| malware | 2865 |
| exploited-in-the-wild | 1726 |
| drop | 1710 |
| spamhaus | 1710 |
| nvd | 1652 |
| Mirai | 1060 |
| ClickFix | 944 |
| etherhiding | 719 |

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
