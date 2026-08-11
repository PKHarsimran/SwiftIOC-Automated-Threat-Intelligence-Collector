# SwiftIOC IOC Summary

_Generated 2026-08-11T01:17:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-11T01:17:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3774 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 128 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7768 |
| Corroborated (2+ sources) | 128 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-11T01:15:24Z |

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
| blocklist_de_ssh | 4970 |
| greensnow_blocklist | 3794 |
| binarydefense_banlist | 3036 |
| ipsum_level5 | 2092 |
| spamhaus_drop | 1687 |
| cisa_kev | 1662 |
| malwarebazaar_recent | 1473 |
| tor_exit_nodes | 1385 |
| threatfox_export_json | 760 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4086 |
| cve | 2512 |
| ipv4_cidr | 1686 |
| url | 644 |
| domain | 412 |
| md5 | 198 |
| ipv4 | 185 |
| sha1 | 180 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4413 |
| cve | 2512 |
| drop | 1686 |
| spamhaus | 1686 |
| exploited-in-the-wild | 1662 |
| Mirai | 1355 |
| threatfox | 1292 |
| nvd | 958 |
| malware_download | 523 |
| high | 438 |

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
