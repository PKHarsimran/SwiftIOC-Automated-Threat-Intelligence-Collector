# SwiftIOC IOC Summary

_Generated 2026-09-23T15:59:47Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-23T15:59:47Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8304 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1131 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1131 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-23T15:54:52Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 11777 |
| binarydefense_banlist | 5581 |
| ipsum_level5 | 4822 |
| greensnow_blocklist | 4806 |
| threatfox_export_json | 3614 |
| nist_nvd_recent | 2692 |
| malwarebazaar_recent | 1735 |
| cisa_kev | 1721 |
| spamhaus_drop | 1712 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2475 |
| sha256 | 2389 |
| domain | 1860 |
| ipv4_cidr | 1707 |
| url | 1070 |
| sha1 | 238 |
| ipv4 | 231 |
| md5 | 30 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3533 |
| malware | 3122 |
| cve | 2475 |
| exploited-in-the-wild | 1721 |
| drop | 1707 |
| spamhaus | 1707 |
| ClickFix | 1281 |
| nvd | 1016 |
| Mirai | 739 |
| malware_download | 735 |

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
