# SwiftIOC IOC Summary

_Generated 2026-08-08T12:36:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-08T12:36:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2846 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 109 |
| Score (min / avg / max) | 78 / 79.6 / 96 |
| High-score indicators (≥80) | 6856 |
| Corroborated (2+ sources) | 109 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-08T12:14:28Z |

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
| blocklist_de_ssh | 4809 |
| greensnow_blocklist | 3386 |
| binarydefense_banlist | 2362 |
| ipsum_level5 | 1774 |
| spamhaus_drop | 1684 |
| cisa_kev | 1662 |
| tor_exit_nodes | 1414 |
| threatfox_export_json | 1364 |
| malwarebazaar_recent | 851 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4385 |
| cve | 2043 |
| ipv4_cidr | 1683 |
| domain | 762 |
| url | 534 |
| ipv4 | 228 |
| md5 | 146 |
| sha1 | 122 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4717 |
| cve | 2043 |
| drop | 1683 |
| spamhaus | 1683 |
| exploited-in-the-wild | 1662 |
| threatfox | 1459 |
| Mirai | 1150 |
| nvd | 475 |
| malware_download | 470 |
| ClearFake | 405 |

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
