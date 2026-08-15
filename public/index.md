# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-15T16:17:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-15T16:17:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 1982 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 218 |
| Score (min / avg / max) | 79 / 80.0 / 96 |
| High-score indicators (≥80) | 8726 |
| Corroborated (2+ sources) | 218 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-15T16:05:06Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]40[.]5` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 88, 4 sources |
| ipv4: `94[.]154[.]43[.]46` | score 88, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4933 |
| greensnow_blocklist | 2929 |
| threatfox_export_json | 2769 |
| ipsum_level5 | 1803 |
| spamhaus_drop | 1687 |
| cisa_kev | 1665 |
| tor_exit_nodes | 1385 |
| malwarebazaar_recent | 839 |
| et_compromised | 551 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2968 |
| cve | 2030 |
| domain | 1967 |
| ipv4_cidr | 1686 |
| url | 652 |
| ipv4 | 216 |
| md5 | 201 |
| sha1 | 183 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3202 |
| threatfox | 2990 |
| cve | 2030 |
| drop | 1686 |
| spamhaus | 1686 |
| exploited-in-the-wild | 1665 |
| ClickFix | 1614 |
| etherhiding | 1412 |
| Sepolia | 927 |
| Mirai | 916 |

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
