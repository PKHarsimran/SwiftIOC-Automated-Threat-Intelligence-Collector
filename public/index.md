# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-25T02:11:17Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-25T02:11:17Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3903 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 1008 |
| Score (min / avg / max) | 76 / 79.4 / 96 |
| High-score indicators (≥80) | 7253 |
| Corroborated (2+ sources) | 1008 |
| Earliest first_seen | 2000-12-19T05:00:00Z |
| Newest first_seen | 2026-07-25T02:10:55Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| cve: `CVE-2024-30088` | score 88, 2 sources |
| cve: `CVE-2024-35250` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4543 |
| binarydefense_banlist | 4119 |
| greensnow_blocklist | 3777 |
| spamhaus_drop | 1670 |
| cisa_kev | 1653 |
| ipsum_level5 | 1640 |
| threatfox_export_json | 1457 |
| tor_exit_nodes | 1387 |
| malwarebazaar_recent | 741 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2891 |
| sha256 | 2233 |
| ipv4_cidr | 1669 |
| ipv4 | 1198 |
| url | 799 |
| domain | 547 |
| md5 | 283 |
| sha1 | 283 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 2891 |
| malware | 2357 |
| threatfox | 1988 |
| drop | 1669 |
| spamhaus | 1669 |
| exploited-in-the-wild | 1653 |
| nvd | 1245 |
| blocklist | 995 |
| aggregated | 988 |
| ipsum | 988 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 185[.]65[.]202[.]199 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 192[.]142[.]28[.]77 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]50 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 103[.]167[.]88[.]166 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 107[.]189[.]10[.]124 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 117[.]175[.]140[.]121 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
