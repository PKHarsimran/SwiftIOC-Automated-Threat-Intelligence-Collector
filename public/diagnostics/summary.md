# SwiftIOC IOC Summary

_Generated 2026-08-09T16:27:46Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-09T16:27:46Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3111 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 114 |
| Score (min / avg / max) | 77 / 79.7 / 96 |
| High-score indicators (≥80) | 7057 |
| Corroborated (2+ sources) | 114 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-09T16:19:22Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4: `91[.]92[.]40[.]5` | score 96, 3 sources |
| ipv4: `94[.]154[.]43[.]46` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4956 |
| greensnow_blocklist | 3308 |
| binarydefense_banlist | 2604 |
| ipsum_level5 | 1947 |
| spamhaus_drop | 1684 |
| cisa_kev | 1662 |
| tor_exit_nodes | 1408 |
| threatfox_export_json | 1154 |
| malwarebazaar_recent | 776 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3992 |
| cve | 2288 |
| ipv4_cidr | 1683 |
| url | 694 |
| domain | 620 |
| ipv4 | 226 |
| md5 | 212 |
| sha1 | 188 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4431 |
| cve | 2288 |
| drop | 1683 |
| spamhaus | 1683 |
| exploited-in-the-wild | 1662 |
| threatfox | 1502 |
| Mirai | 1411 |
| nvd | 720 |
| malware_download | 642 |
| ClearFake | 385 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]40[.]5 | ci_army_list, et_compromised, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]46 | binarydefense_banlist, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
