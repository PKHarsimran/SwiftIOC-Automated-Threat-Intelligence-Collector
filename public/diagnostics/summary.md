# SwiftIOC IOC Summary

_Generated 2026-08-13T16:51:42Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-13T16:51:42Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3560 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 199 |
| Score (min / avg / max) | 77 / 80.0 / 96 |
| High-score indicators (≥80) | 8912 |
| Corroborated (2+ sources) | 199 |
| Earliest first_seen | 2017-02-03T07:59:00Z |
| Newest first_seen | 2026-08-13T16:51:35Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]40[.]5` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]46` | score 96, 3 sources |
| ipv4: `176[.]65[.]139[.]236` | score 88, 2 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5339 |
| binarydefense_banlist | 3541 |
| greensnow_blocklist | 3221 |
| ipsum_level5 | 2056 |
| spamhaus_drop | 1686 |
| cisa_kev | 1665 |
| threatfox_export_json | 1441 |
| tor_exit_nodes | 1332 |
| malwarebazaar_recent | 1243 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3768 |
| cve | 2238 |
| ipv4_cidr | 1688 |
| url | 937 |
| domain | 730 |
| ipv4 | 271 |
| md5 | 139 |
| sha1 | 132 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4364 |
| cve | 2238 |
| drop | 1688 |
| spamhaus | 1688 |
| exploited-in-the-wild | 1665 |
| threatfox | 1621 |
| Mirai | 1071 |
| malware_download | 755 |
| nvd | 745 |
| Vidar | 509 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]40[.]5 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]46 | binarydefense_banlist, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
