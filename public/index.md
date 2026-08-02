# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-02T13:09:44Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-02T13:09:44Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2106 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 413 |
| Score (min / avg / max) | 76 / 79.6 / 96 |
| High-score indicators (≥80) | 6731 |
| Corroborated (2+ sources) | 413 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-02T13:09:38Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `45[.]90[.]163[.]37` | score 92, 3 sources |
| ipv4: `94[.]154[.]43[.]102` | score 90, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4451 |
| greensnow_blocklist | 2769 |
| ipsum_level5 | 1732 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| tor_exit_nodes | 1405 |
| threatfox_export_json | 997 |
| et_compromised | 586 |
| malwarebazaar_recent | 557 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2493 |
| cve | 2437 |
| ipv4_cidr | 1665 |
| domain | 1441 |
| url | 605 |
| ipv4 | 563 |
| md5 | 363 |
| sha1 | 336 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 2721 |
| malware | 2704 |
| cve | 2437 |
| drop | 1665 |
| spamhaus | 1665 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1046 |
| etherhiding | 1005 |
| nvd | 804 |
| Mirai | 692 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 192[.]142[.]28[.]77 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]62 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 199[.]45[.]155[.]105 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 66[.]132[.]195[.]56 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 77[.]90[.]185[.]20 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 106[.]15[.]238[.]36 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |
| ipv4: 107[.]175[.]227[.]45 | blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
