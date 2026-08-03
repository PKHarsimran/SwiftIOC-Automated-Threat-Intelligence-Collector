# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-03T06:55:12Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-03T06:55:12Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2370 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 476 |
| Score (min / avg / max) | 76 / 79.4 / 96 |
| High-score indicators (≥80) | 6501 |
| Corroborated (2+ sources) | 476 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-03T06:55:06Z |

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
| blocklist_de_ssh | 4400 |
| greensnow_blocklist | 3287 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| ipsum_level5 | 1622 |
| tor_exit_nodes | 1396 |
| threatfox_export_json | 1049 |
| binarydefense_banlist | 825 |
| et_compromised | 586 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2755 |
| sha256 | 2723 |
| ipv4_cidr | 1664 |
| domain | 679 |
| url | 641 |
| ipv4 | 638 |
| md5 | 415 |
| sha1 | 388 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 2922 |
| cve | 2755 |
| threatfox | 2121 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1656 |
| nvd | 1124 |
| Mirai | 755 |
| high | 660 |
| malware_download | 597 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 167[.]94[.]146[.]62 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 77[.]90[.]185[.]20 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]230 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 106[.]15[.]238[.]36 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 119[.]148[.]49[.]82 | binarydefense_banlist, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 152[.]32[.]174[.]171 | blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
