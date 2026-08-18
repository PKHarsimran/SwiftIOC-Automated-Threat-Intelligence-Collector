# SwiftIOC IOC Summary

_Generated 2026-08-18T20:17:20Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-18T20:17:20Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1886 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 210 |
| Score (min / avg / max) | 79 / 80.1 / 96 |
| High-score indicators (≥80) | 9575 |
| Corroborated (2+ sources) | 210 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-18T20:05:09Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]40[.]5` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
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
| blocklist_de_ssh | 4807 |
| threatfox_export_json | 4016 |
| greensnow_blocklist | 2781 |
| spamhaus_drop | 1693 |
| cisa_kev | 1670 |
| tor_exit_nodes | 1540 |
| binarydefense_banlist | 1488 |
| ipsum_level5 | 988 |
| malwarebazaar_recent | 959 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| domain | 2901 |
| cve | 2182 |
| sha256 | 1822 |
| ipv4_cidr | 1692 |
| url | 829 |
| ipv4 | 244 |
| md5 | 118 |
| sha1 | 115 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3790 |
| malware | 2236 |
| cve | 2182 |
| etherhiding | 1962 |
| drop | 1692 |
| spamhaus | 1692 |
| exploited-in-the-wild | 1670 |
| ClickFix | 800 |
| nvd | 709 |
| Mirai | 650 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]40[.]5 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0188 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0738 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-1428 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-2861 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-0507 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
