# SwiftIOC IOC Summary

_Generated 2026-08-02T02:18:38Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-02T02:18:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2439 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 95 |
| Score (min / avg / max) | 76 / 79.6 / 96 |
| High-score indicators (≥80) | 7687 |
| Corroborated (2+ sources) | 95 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-02T02:18:30Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 sources |
| ipv4: `94[.]154[.]43[.]102` | score 94, 4 sources |
| ipv4: `217[.]60[.]195[.]187` | score 91, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4406 |
| greensnow_blocklist | 3453 |
| threatfox_export_json | 1933 |
| ipsum_level5 | 1732 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| tor_exit_nodes | 1407 |
| malwarebazaar_recent | 615 |
| et_compromised | 586 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2426 |
| sha256 | 2341 |
| domain | 1919 |
| ipv4_cidr | 1665 |
| url | 584 |
| md5 | 363 |
| sha1 | 336 |
| ipv4 | 269 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3213 |
| malware | 2540 |
| cve | 2426 |
| drop | 1665 |
| spamhaus | 1665 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1496 |
| etherhiding | 1453 |
| nvd | 793 |
| Mirai | 636 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 192[.]142[.]28[.]77 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]62 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 199[.]45[.]155[.]105 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 77[.]90[.]185[.]20 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 135[.]119[.]112[.]132 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |
| ipv4: 142[.]93[.]95[.]58 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |
| ipv4: 143[.]198[.]73[.]73 | binarydefense_banlist, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
