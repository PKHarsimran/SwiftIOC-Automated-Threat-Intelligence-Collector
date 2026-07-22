# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-22T06:25:12Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-22T06:25:12Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4428 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 3184 |
| Score (min / avg / max) | 68 / 77.8 / 96 |
| High-score indicators (≥80) | 5885 |
| Corroborated (2+ sources) | 3184 |
| Earliest first_seen | 2009-11-03T16:30:12Z |
| Newest first_seen | 2026-07-22T06:23:54Z |

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
| cve: `CVE-2026-0770` | score 88, 2 sources |
| cve: `CVE-2026-60137` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5809 |
| greensnow_blocklist | 4130 |
| binarydefense_banlist | 3507 |
| ipsum_level5 | 2325 |
| spamhaus_drop | 1669 |
| cisa_kev | 1651 |
| tor_exit_nodes | 1422 |
| threatfox_export_json | 993 |
| malwarebazaar_recent | 749 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 3450 |
| cve | 2296 |
| ipv4_cidr | 1682 |
| domain | 916 |
| sha256 | 878 |
| url | 529 |
| ja3 | 97 |
| md5 | 76 |
| sha1 | 76 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 3170 |
| aggregated | 2934 |
| ipsum | 2934 |
| multi-list | 2934 |
| cve | 2296 |
| scanner | 2147 |
| ssh | 1785 |
| bruteforce | 1784 |
| cins | 1751 |
| drop | 1682 |

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
