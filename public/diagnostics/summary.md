# SwiftIOC IOC Summary

_Generated 2026-10-02T10:15:52Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-02T10:15:52Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4710 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1442 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1442 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-02T10:04:13Z |

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
| ipv4: `176[.]65[.]148[.]49` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 4372 |
| greensnow_blocklist | 3533 |
| blocklist_de_ssh | 2761 |
| nist_nvd_recent | 2600 |
| threatfox_export_json | 2357 |
| cisa_kev | 1731 |
| spamhaus_drop | 1693 |
| tor_exit_nodes | 1365 |
| malwarebazaar_recent | 1213 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3212 |
| cve | 2599 |
| ipv4_cidr | 1692 |
| url | 1104 |
| domain | 975 |
| ipv4 | 242 |
| sha1 | 140 |
| md5 | 36 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3534 |
| threatfox | 3285 |
| cve | 2599 |
| exploited-in-the-wild | 1731 |
| drop | 1692 |
| spamhaus | 1692 |
| nvd | 1172 |
| Mirai | 1130 |
| ClickFix | 833 |
| malware_download | 749 |

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
