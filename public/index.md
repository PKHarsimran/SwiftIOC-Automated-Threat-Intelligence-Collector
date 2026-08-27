# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-27T06:54:36Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-27T06:54:36Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1991 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 229 |
| Score (min / avg / max) | 77 / 79.8 / 96 |
| High-score indicators (≥80) | 7193 |
| Corroborated (2+ sources) | 229 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-27T06:49:57Z |

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
| blocklist_de_ssh | 5707 |
| greensnow_blocklist | 3645 |
| threatfox_export_json | 1969 |
| spamhaus_drop | 1704 |
| cisa_kev | 1682 |
| tor_exit_nodes | 1407 |
| ipsum_level5 | 990 |
| malwarebazaar_recent | 861 |
| et_compromised | 542 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3315 |
| cve | 2589 |
| ipv4_cidr | 1703 |
| url | 760 |
| domain | 698 |
| ipv4 | 410 |
| md5 | 217 |
| sha1 | 211 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3468 |
| cve | 2589 |
| threatfox | 2143 |
| drop | 1703 |
| spamhaus | 1703 |
| exploited-in-the-wild | 1682 |
| Mirai | 1180 |
| nvd | 1120 |
| high | 587 |
| malware_download | 428 |

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
