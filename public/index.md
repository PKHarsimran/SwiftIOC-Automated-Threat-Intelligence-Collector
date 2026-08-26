# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-26T04:37:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-26T04:37:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1917 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 221 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7207 |
| Corroborated (2+ sources) | 221 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-26T04:27:22Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `5[.]61[.]209[.]44` | score 93, 4 sources |
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
| blocklist_de_ssh | 5334 |
| greensnow_blocklist | 3678 |
| threatfox_export_json | 1984 |
| spamhaus_drop | 1703 |
| cisa_kev | 1676 |
| tor_exit_nodes | 1407 |
| ipsum_level5 | 951 |
| malwarebazaar_recent | 686 |
| et_compromised | 546 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3248 |
| cve | 2533 |
| ipv4_cidr | 1702 |
| url | 759 |
| domain | 651 |
| ipv4 | 450 |
| md5 | 283 |
| sha1 | 277 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3275 |
| cve | 2533 |
| threatfox | 2390 |
| drop | 1702 |
| spamhaus | 1702 |
| exploited-in-the-wild | 1676 |
| Mirai | 1192 |
| nvd | 1064 |
| high | 561 |
| malware_download | 368 |

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
