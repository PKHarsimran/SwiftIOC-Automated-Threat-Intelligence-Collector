# SwiftIOC IOC Summary

_Generated 2026-08-23T04:31:10Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-23T04:31:10Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2103 |
| Sources reporting | 16 |
| Indicator types | 9 |
| Multi-source overlaps | 432 |
| Score (min / avg / max) | 76 / 79.8 / 96 |
| High-score indicators (≥80) | 6969 |
| Corroborated (2+ sources) | 432 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-23T04:31:04Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
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
| greensnow_blocklist | 3343 |
| binarydefense_banlist | 2918 |
| spamhaus_drop | 1699 |
| cisa_kev | 1674 |
| threatfox_export_json | 1533 |
| tor_exit_nodes | 1373 |
| ipsum_level5 | 1204 |
| malwarebazaar_recent | 841 |
| et_compromised | 544 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3483 |
| cve | 2460 |
| ipv4_cidr | 1698 |
| domain | 874 |
| ipv4 | 516 |
| url | 511 |
| md5 | 184 |
| sha1 | 177 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3632 |
| cve | 2460 |
| threatfox | 1901 |
| drop | 1698 |
| spamhaus | 1698 |
| exploited-in-the-wild | 1674 |
| Mirai | 1367 |
| nvd | 988 |
| high | 530 |
| malware_download | 382 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]102 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 144[.]225[.]6[.]182 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 160[.]119[.]76[.]27 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]48 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]54 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]55 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]57 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]58 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]59 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
