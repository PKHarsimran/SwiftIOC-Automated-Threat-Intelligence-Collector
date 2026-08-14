# SwiftIOC IOC Summary

_Generated 2026-08-14T09:03:51Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-14T09:03:51Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3838 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 218 |
| Score (min / avg / max) | 79 / 80.0 / 96 |
| High-score indicators (≥80) | 8019 |
| Corroborated (2+ sources) | 218 |
| Earliest first_seen | 2017-02-03T07:59:00Z |
| Newest first_seen | 2026-08-14T09:00:09Z |

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
| blocklist_de_ssh | 4576 |
| greensnow_blocklist | 3823 |
| binarydefense_banlist | 3785 |
| ipsum_level5 | 2188 |
| spamhaus_drop | 1686 |
| cisa_kev | 1665 |
| threatfox_export_json | 1635 |
| tor_exit_nodes | 1334 |
| malwarebazaar_recent | 934 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4175 |
| cve | 2130 |
| ipv4_cidr | 1685 |
| domain | 784 |
| url | 580 |
| ipv4 | 269 |
| md5 | 148 |
| sha1 | 132 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4393 |
| cve | 2130 |
| threatfox | 1706 |
| drop | 1685 |
| spamhaus | 1685 |
| exploited-in-the-wild | 1665 |
| Mirai | 1209 |
| nvd | 654 |
| Vidar | 600 |
| malware_download | 383 |

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
