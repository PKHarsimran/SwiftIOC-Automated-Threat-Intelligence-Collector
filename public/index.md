# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-03T02:22:42Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-03T02:22:42Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2542 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 39 |
| Score (min / avg / max) | 77 / 79.5 / 96 |
| High-score indicators (≥80) | 6522 |
| Corroborated (2+ sources) | 39 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-03T02:18:28Z |

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
| blocklist_de_ssh | 4404 |
| greensnow_blocklist | 3207 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| ipsum_level5 | 1622 |
| tor_exit_nodes | 1403 |
| threatfox_export_json | 1057 |
| binarydefense_banlist | 825 |
| et_compromised | 586 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2681 |
| sha256 | 2650 |
| ipv4_cidr | 1664 |
| domain | 1330 |
| url | 585 |
| md5 | 415 |
| sha1 | 388 |
| ipv4 | 190 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 2795 |
| threatfox | 2759 |
| cve | 2681 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1656 |
| nvd | 1050 |
| ClickFix | 966 |
| etherhiding | 923 |
| Mirai | 726 |

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
