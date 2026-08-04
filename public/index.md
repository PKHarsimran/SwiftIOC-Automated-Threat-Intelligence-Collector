# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-04T02:04:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-04T02:04:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2752 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 41 |
| Score (min / avg / max) | 78 / 79.8 / 96 |
| High-score indicators (≥80) | 8151 |
| Corroborated (2+ sources) | 41 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-04T01:53:29Z |

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
| blocklist_de_ssh | 4650 |
| greensnow_blocklist | 3385 |
| ipsum_level5 | 1772 |
| spamhaus_drop | 1665 |
| cisa_kev | 1657 |
| tor_exit_nodes | 1398 |
| binarydefense_banlist | 1198 |
| threatfox_export_json | 903 |
| et_compromised | 559 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4008 |
| cve | 2355 |
| ipv4_cidr | 1664 |
| url | 625 |
| domain | 458 |
| md5 | 322 |
| sha1 | 284 |
| ipv4 | 187 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4193 |
| cve | 2355 |
| threatfox | 1688 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1657 |
| Mirai | 738 |
| nvd | 724 |
| malware_download | 491 |
| high | 312 |

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
