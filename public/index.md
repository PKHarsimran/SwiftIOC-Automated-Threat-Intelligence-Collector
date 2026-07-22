# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-22T13:41:39Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-22T13:41:39Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4179 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 2831 |
| Score (min / avg / max) | 68 / 78.2 / 96 |
| High-score indicators (≥80) | 5838 |
| Corroborated (2+ sources) | 2831 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-22T13:39:52Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| ipv4: `94[.]154[.]43[.]102` | score 88, 2 sources |
| cve: `CVE-2024-30088` | score 88, 2 sources |
| cve: `CVE-2024-35250` | score 88, 2 sources |
| cve: `CVE-2026-0770` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 9823 |
| binarydefense_banlist | 3507 |
| greensnow_blocklist | 3486 |
| ipsum_level5 | 2325 |
| spamhaus_drop | 1669 |
| cisa_kev | 1651 |
| tor_exit_nodes | 1417 |
| threatfox_export_json | 801 |
| malwarebazaar_recent | 752 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 3108 |
| cve | 2307 |
| ipv4_cidr | 1682 |
| sha256 | 1066 |
| domain | 936 |
| url | 652 |
| ja3 | 97 |
| md5 | 76 |
| sha1 | 76 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 2817 |
| aggregated | 2713 |
| ipsum | 2713 |
| multi-list | 2713 |
| cve | 2307 |
| scanner | 1961 |
| drop | 1682 |
| spamhaus | 1682 |
| threatfox | 1660 |
| exploited-in-the-wild | 1651 |

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
| ipv4: 117[.]175[.]140[.]121 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
