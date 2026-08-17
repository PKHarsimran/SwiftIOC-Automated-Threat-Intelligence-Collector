# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-17T12:36:03Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-17T12:36:03Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1562 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 210 |
| Score (min / avg / max) | 77 / 79.9 / 96 |
| High-score indicators (≥80) | 7440 |
| Corroborated (2+ sources) | 210 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-17T12:33:11Z |

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
| blocklist_de_ssh | 4877 |
| greensnow_blocklist | 2664 |
| spamhaus_drop | 1688 |
| cisa_kev | 1665 |
| threatfox_export_json | 1624 |
| tor_exit_nodes | 1505 |
| binarydefense_banlist | 1161 |
| ipsum_level5 | 814 |
| malwarebazaar_recent | 644 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3453 |
| cve | 2258 |
| ipv4_cidr | 1687 |
| url | 836 |
| domain | 784 |
| md5 | 309 |
| sha1 | 298 |
| ipv4 | 278 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3766 |
| cve | 2258 |
| threatfox | 2191 |
| drop | 1687 |
| spamhaus | 1687 |
| exploited-in-the-wild | 1665 |
| Mirai | 1097 |
| nvd | 788 |
| malware_download | 639 |
| Vidar | 564 |

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
