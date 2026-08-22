# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-22T16:17:36Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-22T16:17:36Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2674 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 772 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 7506 |
| Corroborated (2+ sources) | 772 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-22T16:17:31Z |

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
| blocklist_de_ssh | 5238 |
| greensnow_blocklist | 2896 |
| binarydefense_banlist | 2659 |
| spamhaus_drop | 1699 |
| cisa_kev | 1674 |
| threatfox_export_json | 1470 |
| ipsum_level5 | 1413 |
| tor_exit_nodes | 1372 |
| malwarebazaar_recent | 825 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3308 |
| cve | 2444 |
| ipv4_cidr | 1698 |
| ipv4 | 963 |
| domain | 588 |
| url | 541 |
| md5 | 184 |
| sha1 | 177 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3432 |
| cve | 2444 |
| threatfox | 1777 |
| drop | 1698 |
| spamhaus | 1698 |
| exploited-in-the-wild | 1674 |
| Mirai | 1252 |
| nvd | 972 |
| blocklist | 556 |
| aggregated | 540 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 144[.]225[.]6[.]182 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 160[.]119[.]76[.]27 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]54 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]55 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]57 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]58 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]59 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]60 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]61 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
