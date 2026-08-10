# SwiftIOC IOC Summary

_Generated 2026-08-10T09:13:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-10T09:13:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3093 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 116 |
| Score (min / avg / max) | 78 / 79.7 / 96 |
| High-score indicators (≥80) | 6884 |
| Corroborated (2+ sources) | 116 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-10T09:13:39Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `91[.]92[.]40[.]5` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]46` | score 96, 3 sources |
| ipv4: `130[.]12[.]180[.]51` | score 88, 2 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4858 |
| greensnow_blocklist | 3842 |
| binarydefense_banlist | 2818 |
| ipsum_level5 | 1697 |
| spamhaus_drop | 1686 |
| cisa_kev | 1662 |
| tor_exit_nodes | 1390 |
| threatfox_export_json | 912 |
| malwarebazaar_recent | 861 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3985 |
| cve | 2516 |
| ipv4_cidr | 1686 |
| url | 692 |
| domain | 475 |
| ipv4 | 200 |
| md5 | 187 |
| sha1 | 162 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4392 |
| cve | 2516 |
| drop | 1686 |
| spamhaus | 1686 |
| exploited-in-the-wild | 1662 |
| Mirai | 1482 |
| threatfox | 1311 |
| nvd | 948 |
| malware_download | 585 |
| high | 425 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]40[.]5 | ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]46 | binarydefense_banlist, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
