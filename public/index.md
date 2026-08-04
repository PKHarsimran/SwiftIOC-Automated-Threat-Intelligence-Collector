# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-04T10:32:16Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-04T10:32:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2373 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 83 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-score indicators (≥80) | 8453 |
| Corroborated (2+ sources) | 83 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-04T10:24:39Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 93, 4 sources |
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
| blocklist_de_ssh | 5085 |
| greensnow_blocklist | 2371 |
| ipsum_level5 | 1772 |
| spamhaus_drop | 1665 |
| cisa_kev | 1657 |
| tor_exit_nodes | 1398 |
| binarydefense_banlist | 1198 |
| threatfox_export_json | 992 |
| malwarebazaar_recent | 787 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3941 |
| cve | 2378 |
| ipv4_cidr | 1664 |
| url | 708 |
| domain | 396 |
| md5 | 292 |
| sha1 | 284 |
| ipv4 | 240 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4192 |
| cve | 2378 |
| threatfox | 1666 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1657 |
| Mirai | 847 |
| nvd | 790 |
| malware_download | 556 |
| high | 413 |

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
