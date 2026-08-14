# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-14T12:54:58Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-14T12:54:58Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3669 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 218 |
| Score (min / avg / max) | 79 / 80.1 / 96 |
| High-score indicators (≥80) | 8816 |
| Corroborated (2+ sources) | 218 |
| Earliest first_seen | 2017-02-03T07:59:00Z |
| Newest first_seen | 2026-08-14T12:45:45Z |

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
| blocklist_de_ssh | 4668 |
| binarydefense_banlist | 3785 |
| greensnow_blocklist | 3202 |
| ipsum_level5 | 2188 |
| threatfox_export_json | 1960 |
| spamhaus_drop | 1684 |
| cisa_kev | 1665 |
| tor_exit_nodes | 1331 |
| malwarebazaar_recent | 970 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3701 |
| cve | 2029 |
| ipv4_cidr | 1685 |
| domain | 1121 |
| url | 674 |
| ipv4 | 275 |
| md5 | 217 |
| sha1 | 201 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3944 |
| threatfox | 2256 |
| cve | 2029 |
| drop | 1685 |
| spamhaus | 1685 |
| exploited-in-the-wild | 1665 |
| Mirai | 953 |
| ClickFix | 631 |
| Vidar | 604 |
| nvd | 553 |

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
