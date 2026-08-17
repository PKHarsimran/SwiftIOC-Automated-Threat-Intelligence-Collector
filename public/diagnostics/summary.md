# SwiftIOC IOC Summary

_Generated 2026-08-17T00:57:49Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-17T00:57:49Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1985 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 209 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7094 |
| Corroborated (2+ sources) | 209 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-17T00:48:21Z |

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
| blocklist_de_ssh | 4950 |
| greensnow_blocklist | 2918 |
| spamhaus_drop | 1687 |
| cisa_kev | 1665 |
| tor_exit_nodes | 1504 |
| ipsum_level5 | 1463 |
| threatfox_export_json | 1256 |
| binarydefense_banlist | 1161 |
| malwarebazaar_recent | 611 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3315 |
| cve | 2112 |
| ipv4_cidr | 1686 |
| domain | 1415 |
| url | 561 |
| md5 | 297 |
| sha1 | 286 |
| ipv4 | 231 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3437 |
| threatfox | 2666 |
| cve | 2112 |
| drop | 1686 |
| spamhaus | 1686 |
| exploited-in-the-wild | 1665 |
| ClickFix | 1120 |
| etherhiding | 1066 |
| Mirai | 1045 |
| Sepolia | 927 |

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
