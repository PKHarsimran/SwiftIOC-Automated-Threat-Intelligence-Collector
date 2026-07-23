# SwiftIOC IOC Summary

_Generated 2026-07-23T10:15:21Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-23T10:15:21Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3754 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 2656 |
| Score (min / avg / max) | 76 / 78.8 / 96 |
| High-score indicators (≥80) | 6597 |
| Corroborated (2+ sources) | 2656 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-23T10:15:03Z |

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
| blocklist_de_ssh | 9602 |
| binarydefense_banlist | 3713 |
| greensnow_blocklist | 2519 |
| ipsum_level5 | 2412 |
| spamhaus_drop | 1670 |
| cisa_kev | 1653 |
| tor_exit_nodes | 1413 |
| threatfox_export_json | 1075 |
| malwarebazaar_recent | 710 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 2865 |
| cve | 2370 |
| ipv4_cidr | 1669 |
| sha256 | 1469 |
| url | 684 |
| domain | 562 |
| md5 | 142 |
| sha1 | 142 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 2646 |
| aggregated | 2615 |
| ipsum | 2615 |
| multi-list | 2615 |
| cve | 2370 |
| malware | 1814 |
| scanner | 1748 |
| drop | 1669 |
| spamhaus | 1669 |
| exploited-in-the-wild | 1653 |

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
