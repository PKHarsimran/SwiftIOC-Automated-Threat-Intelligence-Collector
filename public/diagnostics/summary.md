# SwiftIOC IOC Summary

_Generated 2026-07-20T21:07:46Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-20T21:07:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3430 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 3427 |
| Score (min / avg / max) | 68 / 76.1 / 96 |
| High-score indicators (≥80) | 4803 |
| Corroborated (2+ sources) | 3427 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-20T21:06:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| cve: `CVE-2024-30088` | score 88, 2 sources |
| cve: `CVE-2024-35250` | score 88, 2 sources |
| url: `hxxp://103[.]83[.]87[.]122/telnet[.]sh` | score 88, 2 sources |
| url: `hxxp://193[.]148[.]56[.]98/WQUKDbdzO8yY5asDU6` | score 88, 2 sources |
| url: `hxxps://gerenland[.]click/api/stale[.]msi` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5511 |
| greensnow_blocklist | 3091 |
| binarydefense_banlist | 3029 |
| ipsum_level5 | 2071 |
| spamhaus_drop | 1667 |
| cisa_kev | 1647 |
| tor_exit_nodes | 1427 |
| threatfox_export_json | 958 |
| malwarebazaar_recent | 736 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 3673 |
| cve | 2211 |
| domain | 1840 |
| ipv4_cidr | 1677 |
| url | 351 |
| sha256 | 96 |
| md5 | 76 |
| sha1 | 76 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 3416 |
| threatfox | 2692 |
| aggregated | 2586 |
| ipsum | 2586 |
| multi-list | 2586 |
| scanner | 2416 |
| cve | 2211 |
| cins | 1983 |
| binarydefense | 1706 |
| drop | 1677 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 103[.]167[.]88[.]166 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 107[.]189[.]10[.]124 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 138[.]197[.]39[.]208 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 144[.]31[.]156[.]249 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 148[.]66[.]142[.]9 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 151[.]217[.]4[.]34 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
