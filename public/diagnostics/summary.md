# SwiftIOC IOC Summary

_Generated 2026-08-03T14:30:14Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-03T14:30:14Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5253 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 39 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-score indicators (≥80) | 8454 |
| Corroborated (2+ sources) | 39 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-03T14:21:08Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4: `39[.]108[.]72[.]32` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| ipv4: `94[.]154[.]43[.]249` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| malwarebazaar_recent | 5339 |
| blocklist_de_ssh | 4338 |
| greensnow_blocklist | 2874 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| ipsum_level5 | 1622 |
| tor_exit_nodes | 1398 |
| threatfox_export_json | 1171 |
| binarydefense_banlist | 825 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3800 |
| cve | 2334 |
| ipv4_cidr | 1664 |
| url | 871 |
| domain | 440 |
| md5 | 322 |
| sha1 | 284 |
| ipv4 | 188 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4265 |
| cve | 2334 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1656 |
| threatfox | 1636 |
| malware_download | 771 |
| nvd | 703 |
| Mirai | 643 |
| Mozi | 330 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |
| cve: CVE-2021-22205 | cisa_kev, nist_nvd_recent |
| cve: CVE-2021-40438 | cisa_kev, nist_nvd_recent |
| cve: CVE-2022-47966 | cisa_kev, nist_nvd_recent |
| cve: CVE-2023-27997 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
