# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-21T12:36:05Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-21T12:36:05Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2643 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 844 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 7823 |
| Corroborated (2+ sources) | 844 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-21T12:35:57Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `91[.]92[.]40[.]5` | score 90, 5 sources |
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
| blocklist_de_ssh | 5096 |
| greensnow_blocklist | 2829 |
| binarydefense_banlist | 2399 |
| spamhaus_drop | 1699 |
| cisa_kev | 1673 |
| threatfox_export_json | 1521 |
| tor_exit_nodes | 1515 |
| ipsum_level5 | 1283 |
| malwarebazaar_recent | 1085 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2727 |
| cve | 2253 |
| ipv4_cidr | 1698 |
| ipv4 | 1160 |
| domain | 1124 |
| url | 748 |
| md5 | 98 |
| ja3 | 97 |
| sha1 | 95 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3096 |
| cve | 2253 |
| threatfox | 2228 |
| drop | 1698 |
| spamhaus | 1698 |
| exploited-in-the-wild | 1673 |
| Mirai | 1114 |
| nvd | 780 |
| ClickFix | 738 |
| blocklist | 631 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 160[.]119[.]76[.]27 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]55 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]57 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]58 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]59 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]61 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]218 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 2[.]57[.]122[.]53 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
