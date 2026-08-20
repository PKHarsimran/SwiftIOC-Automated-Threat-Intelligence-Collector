# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-20T12:37:05Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-20T12:37:05Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2442 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 215 |
| Score (min / avg / max) | 79 / 80.0 / 96 |
| High-score indicators (≥80) | 8251 |
| Corroborated (2+ sources) | 215 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-20T12:36:57Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]40[.]5` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]77` | score 90, 5 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.194.92.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4964 |
| greensnow_blocklist | 2865 |
| threatfox_export_json | 2260 |
| binarydefense_banlist | 2081 |
| spamhaus_drop | 1697 |
| cisa_kev | 1671 |
| tor_exit_nodes | 1519 |
| malwarebazaar_recent | 1372 |
| ipsum_level5 | 1239 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| domain | 2346 |
| sha256 | 2269 |
| cve | 2251 |
| ipv4_cidr | 1696 |
| url | 731 |
| ipv4 | 427 |
| ja3 | 97 |
| md5 | 93 |
| sha1 | 90 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3327 |
| malware | 2627 |
| cve | 2251 |
| drop | 1696 |
| spamhaus | 1696 |
| exploited-in-the-wild | 1671 |
| etherhiding | 1653 |
| Mirai | 983 |
| nvd | 780 |
| ClickFix | 741 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]40[.]5 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0188 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0738 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-1428 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-2861 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-0507 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
