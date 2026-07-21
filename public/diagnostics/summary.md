# SwiftIOC IOC Summary

_Generated 2026-07-21T02:12:53Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-21T02:12:53Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4266 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 3435 |
| Score (min / avg / max) | 68 / 76.2 / 96 |
| High-score indicators (≥80) | 4806 |
| Corroborated (2+ sources) | 3435 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-21T02:10:41Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| cve: `CVE-2024-30088` | score 88, 2 sources |
| cve: `CVE-2024-35250` | score 88, 2 sources |
| url: `hxxp://103[.]83[.]87[.]122/telnet[.]sh` | score 88, 2 sources |
| url: `hxxp://193[.]148[.]56[.]98/WQUKDbdzO8yY5asDU6` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5388 |
| greensnow_blocklist | 3647 |
| binarydefense_banlist | 3281 |
| ipsum_level5 | 2328 |
| spamhaus_drop | 1667 |
| cisa_kev | 1647 |
| tor_exit_nodes | 1426 |
| threatfox_export_json | 957 |
| malwarebazaar_recent | 771 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 3672 |
| cve | 2217 |
| domain | 1843 |
| ipv4_cidr | 1677 |
| url | 343 |
| sha256 | 96 |
| md5 | 76 |
| sha1 | 76 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 3423 |
| aggregated | 2927 |
| ipsum | 2927 |
| multi-list | 2927 |
| threatfox | 2679 |
| scanner | 2334 |
| cve | 2217 |
| cins | 1850 |
| ssh | 1755 |
| bruteforce | 1754 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 192[.]142[.]28[.]77 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]50 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 103[.]167[.]88[.]166 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 107[.]189[.]10[.]124 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 119[.]18[.]55[.]118 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
