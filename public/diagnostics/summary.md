# SwiftIOC IOC Summary

_Generated 2026-08-07T08:54:09Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-07T08:54:09Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3199 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 106 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 7312 |
| Corroborated (2+ sources) | 106 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-07T08:36:57Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 8858 |
| greensnow_blocklist | 4199 |
| binarydefense_banlist | 2111 |
| ipsum_level5 | 2004 |
| spamhaus_drop | 1682 |
| cisa_kev | 1661 |
| tor_exit_nodes | 1390 |
| threatfox_export_json | 1015 |
| malwarebazaar_recent | 992 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4389 |
| cve | 2279 |
| ipv4_cidr | 1681 |
| domain | 650 |
| url | 452 |
| ipv4 | 274 |
| md5 | 101 |
| ja3 | 97 |
| sha1 | 77 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4658 |
| cve | 2279 |
| drop | 1681 |
| spamhaus | 1681 |
| exploited-in-the-wild | 1661 |
| threatfox | 1283 |
| Mirai | 1211 |
| nvd | 710 |
| high | 478 |
| malware_download | 376 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-6884 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
