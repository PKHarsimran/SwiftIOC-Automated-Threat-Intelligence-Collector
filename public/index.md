# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-19T16:25:00Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-19T16:25:00Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2234 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 212 |
| Score (min / avg / max) | 79 / 80.1 / 96 |
| High-score indicators (≥80) | 9558 |
| Corroborated (2+ sources) | 212 |
| Earliest first_seen | 2013-09-24T10:35:52Z |
| Newest first_seen | 2026-08-19T16:12:24Z |

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
| blocklist_de_ssh | 4819 |
| threatfox_export_json | 3949 |
| greensnow_blocklist | 2812 |
| binarydefense_banlist | 1821 |
| spamhaus_drop | 1693 |
| cisa_kev | 1670 |
| tor_exit_nodes | 1543 |
| malwarebazaar_recent | 1331 |
| ipsum_level5 | 1228 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| domain | 2562 |
| cve | 2208 |
| sha256 | 2058 |
| ipv4_cidr | 1692 |
| url | 780 |
| ipv4 | 356 |
| md5 | 124 |
| sha1 | 123 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3548 |
| malware | 2452 |
| cve | 2208 |
| etherhiding | 1938 |
| drop | 1692 |
| spamhaus | 1692 |
| exploited-in-the-wild | 1670 |
| Mirai | 899 |
| nvd | 737 |
| ClickFix | 705 |

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
