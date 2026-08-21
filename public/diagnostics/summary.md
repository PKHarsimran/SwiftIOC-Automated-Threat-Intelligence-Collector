# SwiftIOC IOC Summary

_Generated 2026-08-21T01:00:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-21T01:00:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2642 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 229 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 7799 |
| Corroborated (2+ sources) | 229 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-21T01:00:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `91[.]92[.]40[.]5` | score 94, 5 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.194.92.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5104 |
| greensnow_blocklist | 3255 |
| binarydefense_banlist | 2399 |
| threatfox_export_json | 1960 |
| spamhaus_drop | 1699 |
| cisa_kev | 1673 |
| tor_exit_nodes | 1519 |
| ipsum_level5 | 1239 |
| malwarebazaar_recent | 1141 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2462 |
| cve | 2253 |
| domain | 2201 |
| ipv4_cidr | 1698 |
| url | 683 |
| ipv4 | 423 |
| ja3 | 97 |
| md5 | 93 |
| sha1 | 90 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3144 |
| malware | 2792 |
| cve | 2253 |
| drop | 1698 |
| spamhaus | 1698 |
| exploited-in-the-wild | 1673 |
| etherhiding | 1428 |
| Mirai | 1018 |
| ClickFix | 818 |
| nvd | 780 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 160[.]119[.]76[.]27 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]59 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]218 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 2[.]57[.]122[.]53 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 77[.]90[.]185[.]20 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 91[.]92[.]40[.]5 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 167[.]94[.]146[.]62 | binarydefense_banlist, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
