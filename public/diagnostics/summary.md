# SwiftIOC IOC Summary

_Generated 2026-08-06T13:54:12Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-06T13:54:12Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2849 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 107 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 7383 |
| Corroborated (2+ sources) | 107 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-06T13:53:27Z |

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
| blocklist_de_ssh | 9720 |
| greensnow_blocklist | 3669 |
| binarydefense_banlist | 1843 |
| spamhaus_drop | 1682 |
| ipsum_level5 | 1680 |
| cisa_kev | 1661 |
| tor_exit_nodes | 1392 |
| threatfox_export_json | 1108 |
| malwarebazaar_recent | 987 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4021 |
| cve | 2355 |
| ipv4_cidr | 1681 |
| url | 685 |
| domain | 647 |
| ipv4 | 273 |
| md5 | 129 |
| sha1 | 112 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4489 |
| cve | 2355 |
| drop | 1681 |
| spamhaus | 1681 |
| exploited-in-the-wild | 1661 |
| threatfox | 1376 |
| Mirai | 960 |
| nvd | 786 |
| malware_download | 610 |
| high | 523 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
