# SwiftIOC IOC Summary

_Generated 2026-07-26T16:53:22Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-26T16:53:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1645 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 18 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 8296 |
| Corroborated (2+ sources) | 18 |
| Earliest first_seen | 2000-12-19T05:00:00Z |
| Newest first_seen | 2026-07-26T16:50:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
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
| blocklist_de_ssh | 4556 |
| greensnow_blocklist | 2912 |
| threatfox_export_json | 2103 |
| spamhaus_drop | 1668 |
| cisa_kev | 1653 |
| tor_exit_nodes | 1389 |
| ipsum_level5 | 1039 |
| malwarebazaar_recent | 878 |
| et_compromised | 583 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3153 |
| cve | 2432 |
| ipv4_cidr | 1669 |
| url | 657 |
| ipv4 | 587 |
| domain | 559 |
| md5 | 462 |
| sha1 | 384 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3211 |
| threatfox | 2588 |
| cve | 2432 |
| drop | 1669 |
| spamhaus | 1669 |
| exploited-in-the-wild | 1653 |
| Mirai | 792 |
| nvd | 787 |
| malware_download | 544 |
| Popa | 396 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2024-30088 | cisa_kev, nist_nvd_recent |
| cve: CVE-2024-35250 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-0770 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-45498 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-5281 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-60137 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-63030 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-9082 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
