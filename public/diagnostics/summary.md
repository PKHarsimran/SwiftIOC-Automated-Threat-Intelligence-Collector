# SwiftIOC IOC Summary

_Generated 2026-07-27T02:29:15Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-27T02:29:15Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2070 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 19 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 8285 |
| Corroborated (2+ sources) | 19 |
| Earliest first_seen | 2015-04-16T16:59:45Z |
| Newest first_seen | 2026-07-27T02:15:03Z |

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
| blocklist_de_ssh | 4578 |
| greensnow_blocklist | 3414 |
| threatfox_export_json | 1883 |
| spamhaus_drop | 1664 |
| cisa_kev | 1653 |
| tor_exit_nodes | 1381 |
| ipsum_level5 | 990 |
| malwarebazaar_recent | 932 |
| binarydefense_banlist | 771 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3279 |
| cve | 2462 |
| ipv4_cidr | 1667 |
| url | 569 |
| ipv4 | 566 |
| domain | 530 |
| md5 | 454 |
| sha1 | 376 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3299 |
| threatfox | 2473 |
| cve | 2462 |
| drop | 1667 |
| spamhaus | 1667 |
| exploited-in-the-wild | 1653 |
| Mirai | 841 |
| nvd | 817 |
| malware_download | 498 |
| elf | 420 |

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
