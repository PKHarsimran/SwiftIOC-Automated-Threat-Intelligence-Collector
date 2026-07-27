# SwiftIOC IOC Summary

_Generated 2026-07-27T14:22:28Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-27T14:22:28Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1896 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 21 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-score indicators (≥80) | 9060 |
| Corroborated (2+ sources) | 21 |
| Earliest first_seen | 2015-04-16T16:59:45Z |
| Newest first_seen | 2026-07-27T14:15:04Z |

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
| blocklist_de_ssh | 4660 |
| threatfox_export_json | 3142 |
| greensnow_blocklist | 3133 |
| spamhaus_drop | 1664 |
| cisa_kev | 1653 |
| tor_exit_nodes | 1386 |
| ipsum_level5 | 990 |
| malwarebazaar_recent | 974 |
| binarydefense_banlist | 771 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2665 |
| sha256 | 2522 |
| ipv4_cidr | 1663 |
| url | 764 |
| md5 | 715 |
| domain | 611 |
| ipv4 | 557 |
| sha1 | 406 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 2907 |
| malware | 2668 |
| cve | 2665 |
| drop | 1663 |
| spamhaus | 1663 |
| exploited-in-the-wild | 1653 |
| nvd | 1020 |
| malware_download | 639 |
| high | 510 |
| Mirai | 475 |

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
