# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-03T20:58:53Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-03T20:58:53Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2087 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 41 |
| Score (min / avg / max) | 77 / 79.9 / 96 |
| High-score indicators (≥80) | 8523 |
| Corroborated (2+ sources) | 41 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-03T20:49:12Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4: `39[.]108[.]72[.]32` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4371 |
| greensnow_blocklist | 2931 |
| spamhaus_drop | 1665 |
| cisa_kev | 1657 |
| ipsum_level5 | 1622 |
| tor_exit_nodes | 1398 |
| threatfox_export_json | 996 |
| binarydefense_banlist | 825 |
| malwarebazaar_recent | 595 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3945 |
| cve | 2353 |
| ipv4_cidr | 1664 |
| url | 671 |
| domain | 463 |
| md5 | 322 |
| sha1 | 284 |
| ipv4 | 201 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4180 |
| cve | 2353 |
| threatfox | 1703 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1657 |
| nvd | 722 |
| Mirai | 703 |
| malware_download | 541 |
| Mozi | 314 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |
| cve: CVE-2021-22205 | cisa_kev, nist_nvd_recent |
| cve: CVE-2021-40438 | cisa_kev, nist_nvd_recent |
| cve: CVE-2022-47966 | cisa_kev, nist_nvd_recent |
| cve: CVE-2023-27997 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
