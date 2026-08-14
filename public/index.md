# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-14T01:26:35Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-14T01:26:35Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4269 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 200 |
| Score (min / avg / max) | 77 / 80.0 / 96 |
| High-score indicators (≥80) | 8550 |
| Corroborated (2+ sources) | 200 |
| Earliest first_seen | 2017-02-03T07:59:00Z |
| Newest first_seen | 2026-08-14T01:20:13Z |

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
| blocklist_de_ssh | 5470 |
| binarydefense_banlist | 3785 |
| greensnow_blocklist | 3777 |
| ipsum_level5 | 2188 |
| spamhaus_drop | 1686 |
| cisa_kev | 1665 |
| threatfox_export_json | 1405 |
| tor_exit_nodes | 1332 |
| malwarebazaar_recent | 1090 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3935 |
| cve | 2381 |
| ipv4_cidr | 1688 |
| url | 707 |
| domain | 670 |
| ipv4 | 242 |
| md5 | 148 |
| sha1 | 132 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4310 |
| cve | 2381 |
| drop | 1688 |
| spamhaus | 1688 |
| exploited-in-the-wild | 1665 |
| threatfox | 1532 |
| Mirai | 1116 |
| nvd | 889 |
| malware_download | 536 |
| Vidar | 517 |

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
