# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-23T17:15:04Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-23T17:15:04Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3829 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 2286 |
| Score (min / avg / max) | 76 / 79.0 / 96 |
| High-score indicators (≥80) | 6907 |
| Corroborated (2+ sources) | 2286 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-23T17:14:56Z |

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
| blocklist_de_ssh | 9579 |
| binarydefense_banlist | 3713 |
| greensnow_blocklist | 3243 |
| ipsum_level5 | 2412 |
| spamhaus_drop | 1670 |
| cisa_kev | 1653 |
| tor_exit_nodes | 1400 |
| threatfox_export_json | 1229 |
| malwarebazaar_recent | 755 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 2487 |
| cve | 2473 |
| ipv4_cidr | 1669 |
| sha256 | 1603 |
| url | 817 |
| domain | 570 |
| md5 | 142 |
| sha1 | 142 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 2473 |
| blocklist | 2274 |
| aggregated | 2251 |
| ipsum | 2251 |
| multi-list | 2251 |
| malware | 1928 |
| drop | 1669 |
| spamhaus | 1669 |
| exploited-in-the-wild | 1653 |
| scanner | 1640 |

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
