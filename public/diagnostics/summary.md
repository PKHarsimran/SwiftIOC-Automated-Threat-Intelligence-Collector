# SwiftIOC IOC Summary

_Generated 2026-08-27T18:45:35Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-27T18:45:35Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2030 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 232 |
| Score (min / avg / max) | 78 / 79.8 / 96 |
| High-score indicators (≥80) | 7229 |
| Corroborated (2+ sources) | 232 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-27T18:45:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.194.92.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| ipv4_cidr: `91.92.40.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 6613 |
| greensnow_blocklist | 3643 |
| threatfox_export_json | 1864 |
| spamhaus_drop | 1705 |
| cisa_kev | 1685 |
| tor_exit_nodes | 1415 |
| malwarebazaar_recent | 1005 |
| ipsum_level5 | 990 |
| et_compromised | 542 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3338 |
| cve | 2576 |
| ipv4_cidr | 1704 |
| domain | 829 |
| url | 643 |
| ipv4 | 379 |
| md5 | 223 |
| sha1 | 211 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3494 |
| cve | 2576 |
| threatfox | 2132 |
| drop | 1704 |
| spamhaus | 1704 |
| exploited-in-the-wild | 1685 |
| Mirai | 1112 |
| nvd | 1104 |
| high | 571 |
| malware_download | 437 |

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
