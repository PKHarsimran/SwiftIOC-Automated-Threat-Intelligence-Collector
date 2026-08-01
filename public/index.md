# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-01T16:54:41Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-01T16:54:41Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2950 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 39 |
| Score (min / avg / max) | 77 / 79.7 / 96 |
| High-score indicators (≥80) | 8009 |
| Corroborated (2+ sources) | 39 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-01T16:49:50Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 sources |
| ipv4: `217[.]60[.]195[.]187` | score 95, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4414 |
| greensnow_blocklist | 3046 |
| ipsum_level5 | 2078 |
| binarydefense_banlist | 2030 |
| threatfox_export_json | 1974 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| tor_exit_nodes | 1386 |
| malwarebazaar_recent | 638 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2329 |
| sha256 | 2215 |
| domain | 1904 |
| ipv4_cidr | 1665 |
| url | 713 |
| ipv4 | 378 |
| md5 | 363 |
| sha1 | 336 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3377 |
| malware | 2531 |
| cve | 2329 |
| drop | 1665 |
| spamhaus | 1665 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1497 |
| etherhiding | 1453 |
| nvd | 696 |
| malware_download | 642 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 217[.]60[.]195[.]187 | binarydefense_banlist, blocklist_de_ssh, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |
| cve: CVE-2021-22205 | cisa_kev, nist_nvd_recent |
| cve: CVE-2021-40438 | cisa_kev, nist_nvd_recent |
| cve: CVE-2022-47966 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
