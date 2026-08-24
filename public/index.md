# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-24T08:41:44Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-24T08:41:44Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2907 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 219 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7091 |
| Corroborated (2+ sources) | 219 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-24T08:39:29Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.194.92.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5157 |
| greensnow_blocklist | 3165 |
| binarydefense_banlist | 3147 |
| threatfox_export_json | 1865 |
| spamhaus_drop | 1702 |
| cisa_kev | 1674 |
| tor_exit_nodes | 1399 |
| ipsum_level5 | 1310 |
| malwarebazaar_recent | 779 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3683 |
| cve | 2607 |
| ipv4_cidr | 1701 |
| domain | 768 |
| url | 504 |
| md5 | 218 |
| ipv4 | 211 |
| sha1 | 211 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3730 |
| cve | 2607 |
| threatfox | 1864 |
| drop | 1701 |
| spamhaus | 1701 |
| exploited-in-the-wild | 1674 |
| Mirai | 1473 |
| nvd | 1136 |
| high | 577 |
| ClickFix | 336 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0188 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0738 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-1428 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-2861 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-0507 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
