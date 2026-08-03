# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-03T11:17:19Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-03T11:17:19Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3372 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 39 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 7650 |
| Corroborated (2+ sources) | 39 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-03T11:10:06Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |
| ipv4: `94[.]154[.]43[.]249` | score 88, 2 sources |
| ipv4: `95[.]155[.]151[.]113` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4353 |
| greensnow_blocklist | 2775 |
| malwarebazaar_recent | 2393 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| ipsum_level5 | 1622 |
| tor_exit_nodes | 1398 |
| threatfox_export_json | 1149 |
| binarydefense_banlist | 825 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3435 |
| cve | 2472 |
| ipv4_cidr | 1664 |
| url | 888 |
| domain | 438 |
| md5 | 415 |
| sha1 | 388 |
| ipv4 | 203 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3829 |
| cve | 2472 |
| threatfox | 1934 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1656 |
| nvd | 841 |
| malware_download | 792 |
| Mirai | 762 |
| high | 387 |

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
