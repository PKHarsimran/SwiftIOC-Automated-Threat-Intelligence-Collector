# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-15T08:21:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-15T08:21:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2115 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 217 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7763 |
| Corroborated (2+ sources) | 217 |
| Earliest first_seen | 2017-02-03T07:59:00Z |
| Newest first_seen | 2026-08-15T08:05:06Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]40[.]5` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 91, 4 sources |
| ipv4: `94[.]154[.]43[.]46` | score 91, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4795 |
| greensnow_blocklist | 3716 |
| ipsum_level5 | 1803 |
| spamhaus_drop | 1684 |
| cisa_kev | 1665 |
| threatfox_export_json | 1664 |
| tor_exit_nodes | 1376 |
| malwarebazaar_recent | 991 |
| et_compromised | 551 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3893 |
| cve | 2115 |
| ipv4_cidr | 1683 |
| domain | 939 |
| url | 645 |
| ipv4 | 238 |
| md5 | 203 |
| sha1 | 187 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4131 |
| cve | 2115 |
| threatfox | 1978 |
| drop | 1683 |
| spamhaus | 1683 |
| exploited-in-the-wild | 1665 |
| Mirai | 999 |
| Vidar | 649 |
| nvd | 645 |
| ClickFix | 599 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]40[.]5 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]46 | binarydefense_banlist, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0188 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0738 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-1428 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-2861 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
