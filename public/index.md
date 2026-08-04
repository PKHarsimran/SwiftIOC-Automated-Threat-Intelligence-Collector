# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-04T06:24:21Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-04T06:24:21Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1854 |
| Sources reporting | 16 |
| Indicator types | 9 |
| Multi-source overlaps | 83 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-score indicators (≥80) | 8238 |
| Corroborated (2+ sources) | 83 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-04T06:12:12Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 94, 4 sources |
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
| blocklist_de_ssh | 4638 |
| ipsum_level5 | 1772 |
| spamhaus_drop | 1665 |
| cisa_kev | 1657 |
| tor_exit_nodes | 1396 |
| binarydefense_banlist | 1198 |
| threatfox_export_json | 948 |
| malwarebazaar_recent | 655 |
| et_compromised | 559 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4131 |
| cve | 2280 |
| ipv4_cidr | 1664 |
| url | 686 |
| domain | 334 |
| md5 | 329 |
| sha1 | 284 |
| ipv4 | 195 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4369 |
| cve | 2280 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1657 |
| threatfox | 1587 |
| Mirai | 817 |
| nvd | 692 |
| malware_download | 544 |
| elf | 344 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-6884 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
