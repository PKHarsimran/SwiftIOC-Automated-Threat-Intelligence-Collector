# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-21T04:32:28Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-21T04:32:28Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2910 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 787 |
| Score (min / avg / max) | 76 / 79.6 / 96 |
| High-score indicators (≥80) | 7693 |
| Corroborated (2+ sources) | 787 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-21T04:32:05Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `91[.]92[.]40[.]5` | score 93, 5 sources |
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
| blocklist_de_ssh | 5066 |
| greensnow_blocklist | 3267 |
| binarydefense_banlist | 2399 |
| threatfox_export_json | 1938 |
| spamhaus_drop | 1699 |
| cisa_kev | 1673 |
| tor_exit_nodes | 1525 |
| ipsum_level5 | 1283 |
| malwarebazaar_recent | 996 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2490 |
| cve | 2253 |
| ipv4_cidr | 1698 |
| domain | 1584 |
| ipv4 | 985 |
| url | 710 |
| ja3 | 97 |
| md5 | 93 |
| sha1 | 90 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 2846 |
| threatfox | 2532 |
| cve | 2253 |
| drop | 1698 |
| spamhaus | 1698 |
| exploited-in-the-wild | 1673 |
| Mirai | 1021 |
| ClickFix | 820 |
| etherhiding | 801 |
| nvd | 780 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 160[.]119[.]76[.]27 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]57 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]59 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]61 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]218 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 2[.]57[.]122[.]53 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 77[.]239[.]124[.]102 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
