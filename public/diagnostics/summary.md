# SwiftIOC IOC Summary

_Generated 2026-09-23T22:38:30Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-23T22:38:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8301 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1133 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1133 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-23T22:37:52Z |

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
| blocklist_de_ssh | 11706 |
| binarydefense_banlist | 5581 |
| greensnow_blocklist | 4831 |
| ipsum_level5 | 4822 |
| threatfox_export_json | 3972 |
| nist_nvd_recent | 2400 |
| malwarebazaar_recent | 1855 |
| cisa_kev | 1721 |
| spamhaus_drop | 1712 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2543 |
| sha256 | 2365 |
| domain | 1920 |
| ipv4_cidr | 1711 |
| url | 970 |
| sha1 | 238 |
| ipv4 | 223 |
| md5 | 30 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3522 |
| malware | 3062 |
| cve | 2543 |
| exploited-in-the-wild | 1721 |
| drop | 1711 |
| spamhaus | 1711 |
| ClickFix | 1333 |
| nvd | 1085 |
| Mirai | 803 |
| malware_download | 638 |

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
