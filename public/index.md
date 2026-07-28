# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-28T13:54:06Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-28T13:54:06Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2269 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 22 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-score indicators (≥80) | 8680 |
| Corroborated (2+ sources) | 22 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-07-28T13:53:24Z |

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
| blocklist_de_ssh | 4851 |
| threatfox_export_json | 3293 |
| greensnow_blocklist | 3185 |
| spamhaus_drop | 1667 |
| cisa_kev | 1655 |
| tor_exit_nodes | 1384 |
| ipsum_level5 | 1219 |
| binarydefense_banlist | 1106 |
| malwarebazaar_recent | 1019 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2760 |
| cve | 2397 |
| ipv4_cidr | 1666 |
| url | 831 |
| md5 | 721 |
| ipv4 | 566 |
| domain | 537 |
| sha1 | 425 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 2941 |
| threatfox | 2899 |
| cve | 2397 |
| drop | 1666 |
| spamhaus | 1666 |
| exploited-in-the-wild | 1655 |
| nvd | 751 |
| malware_download | 681 |
| elf | 515 |
| Mirai | 506 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2024-30088 | cisa_kev, nist_nvd_recent |
| cve: CVE-2024-35250 | cisa_kev, nist_nvd_recent |
| cve: CVE-2025-68686 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-0770 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-45498 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-5281 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-60137 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-63030 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
