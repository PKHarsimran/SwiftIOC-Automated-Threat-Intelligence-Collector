# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-28T03:59:07Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-28T03:59:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4078 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 233 |
| Score (min / avg / max) | 77 / 79.9 / 96 |
| High-score indicators (≥80) | 7173 |
| Corroborated (2+ sources) | 233 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-28T03:51:31Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.194.92.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 6890 |
| greensnow_blocklist | 4600 |
| ipsum_level5 | 2236 |
| threatfox_export_json | 1761 |
| spamhaus_drop | 1705 |
| cisa_kev | 1685 |
| tor_exit_nodes | 1415 |
| malwarebazaar_recent | 950 |
| binarydefense_banlist | 753 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3491 |
| cve | 2708 |
| ipv4_cidr | 1704 |
| url | 573 |
| domain | 549 |
| ipv4 | 362 |
| md5 | 264 |
| sha1 | 252 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3543 |
| cve | 2708 |
| threatfox | 1951 |
| drop | 1704 |
| spamhaus | 1704 |
| exploited-in-the-wild | 1685 |
| nvd | 1237 |
| Mirai | 1152 |
| high | 632 |
| malware_download | 374 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0188 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0738 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-1428 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-2861 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-0507 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
