# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-20T06:41:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-20T06:41:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3792 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 3964 |
| Score (min / avg / max) | 68 / 75.7 / 88 |
| High-score indicators (≥80) | 4343 |
| Corroborated (2+ sources) | 3964 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-20T06:41:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| url: `hxxp://103[.]83[.]87[.]122/telnet[.]sh` | score 88, 2 sources |
| url: `hxxp://193[.]148[.]56[.]98/WQUKDbdzO8yY5asDU6` | score 88, 2 sources |
| url: `hxxps://gerenland[.]click/api/stale[.]msi` | score 88, 2 sources |
| url: `hxxps://gerenland[.]click/flask/whales[.]msi` | score 88, 2 sources |
| url: `hxxp://41[.]216[.]189[.]236/nz[.]sh` | score 80, 2 sources |
| sha1: `0301c109feb04625b760b29cc34fceadd8c62e6f` | score 80, 1 source |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4984 |
| greensnow_blocklist | 3404 |
| binarydefense_banlist | 3029 |
| ipsum_level5 | 2071 |
| spamhaus_drop | 1678 |
| cisa_kev | 1647 |
| tor_exit_nodes | 1423 |
| threatfox_export_json | 808 |
| malwarebazaar_recent | 656 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4163 |
| cve | 1933 |
| domain | 1748 |
| ipv4_cidr | 1677 |
| url | 312 |
| sha256 | 69 |
| md5 | 49 |
| sha1 | 49 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 3955 |
| aggregated | 3036 |
| ipsum | 3036 |
| multi-list | 3036 |
| scanner | 2677 |
| threatfox | 2430 |
| cins | 2225 |
| cve | 1933 |
| ssh | 1863 |
| bruteforce | 1862 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 107[.]189[.]10[.]124 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 144[.]31[.]156[.]249 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 148[.]66[.]142[.]9 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 151[.]217[.]4[.]34 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 159[.]65[.]143[.]47 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]49 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
