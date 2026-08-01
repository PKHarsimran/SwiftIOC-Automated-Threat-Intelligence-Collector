# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-01T20:43:48Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-01T20:43:48Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2923 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 180 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 7834 |
| Corroborated (2+ sources) | 180 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-01T20:43:41Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 sources |
| ipv4: `217[.]60[.]195[.]187` | score 93, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4387 |
| greensnow_blocklist | 2959 |
| ipsum_level5 | 2078 |
| binarydefense_banlist | 2030 |
| threatfox_export_json | 1928 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| tor_exit_nodes | 1385 |
| malwarebazaar_recent | 604 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2338 |
| sha256 | 2259 |
| domain | 1922 |
| ipv4_cidr | 1665 |
| url | 648 |
| ipv4 | 372 |
| md5 | 363 |
| sha1 | 336 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3240 |
| malware | 2516 |
| cve | 2338 |
| drop | 1665 |
| spamhaus | 1665 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1497 |
| etherhiding | 1453 |
| nvd | 705 |
| Mirai | 587 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 167[.]94[.]146[.]62 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 192[.]142[.]28[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 118[.]216[.]88[.]229 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 143[.]198[.]73[.]73 | binarydefense_banlist, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 144[.]202[.]92[.]17 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |
| ipv4: 147[.]185[.]133[.]106 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |
| ipv4: 165[.]232[.]118[.]73 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
