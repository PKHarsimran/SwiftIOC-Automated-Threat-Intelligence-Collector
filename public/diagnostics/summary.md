# SwiftIOC IOC Summary

_Generated 2026-08-09T12:38:50Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-09T12:38:50Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3161 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 194 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 7040 |
| Corroborated (2+ sources) | 194 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-09T12:38:45Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4: `91[.]92[.]40[.]5` | score 96, 3 sources |
| ipv4: `94[.]154[.]43[.]46` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4854 |
| greensnow_blocklist | 3265 |
| binarydefense_banlist | 2604 |
| ipsum_level5 | 1947 |
| spamhaus_drop | 1684 |
| cisa_kev | 1662 |
| threatfox_export_json | 1473 |
| tor_exit_nodes | 1408 |
| malwarebazaar_recent | 684 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3850 |
| cve | 2234 |
| ipv4_cidr | 1683 |
| url | 738 |
| domain | 681 |
| ipv4 | 317 |
| md5 | 212 |
| sha1 | 188 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4320 |
| cve | 2234 |
| drop | 1683 |
| spamhaus | 1683 |
| exploited-in-the-wild | 1662 |
| threatfox | 1587 |
| Mirai | 1389 |
| malware_download | 673 |
| nvd | 666 |
| ClearFake | 438 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 119[.]148[.]49[.]82 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 148[.]66[.]142[.]9 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]48 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]51 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]52 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]53 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 77[.]90[.]185[.]20 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
