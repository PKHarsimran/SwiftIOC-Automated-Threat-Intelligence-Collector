# SwiftIOC IOC Summary

_Generated 2026-08-25T00:58:58Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-25T00:58:58Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2802 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 218 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7104 |
| Corroborated (2+ sources) | 218 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-25T00:53:27Z |

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
| blocklist_de_ssh | 5179 |
| greensnow_blocklist | 3374 |
| binarydefense_banlist | 3163 |
| spamhaus_drop | 1702 |
| cisa_kev | 1675 |
| threatfox_export_json | 1639 |
| tor_exit_nodes | 1398 |
| ipsum_level5 | 1310 |
| malwarebazaar_recent | 756 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3765 |
| cve | 2450 |
| ipv4_cidr | 1704 |
| domain | 700 |
| url | 587 |
| ipv4 | 268 |
| md5 | 218 |
| sha1 | 211 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3800 |
| cve | 2450 |
| threatfox | 1946 |
| drop | 1704 |
| spamhaus | 1704 |
| exploited-in-the-wild | 1675 |
| Mirai | 1511 |
| nvd | 979 |
| high | 508 |
| ClickFix | 376 |

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
