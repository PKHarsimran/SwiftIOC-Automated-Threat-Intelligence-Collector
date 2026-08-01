# SwiftIOC IOC Summary

_Generated 2026-08-01T09:53:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-01T09:53:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3165 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 326 |
| Score (min / avg / max) | 76 / 79.7 / 96 |
| High-score indicators (≥80) | 8012 |
| Corroborated (2+ sources) | 326 |
| Earliest first_seen | 2013-03-22T21:55:00Z |
| Newest first_seen | 2026-08-01T09:53:28Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4: `217[.]60[.]195[.]187` | score 96, 3 sources |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4463 |
| greensnow_blocklist | 3620 |
| ipsum_level5 | 2078 |
| binarydefense_banlist | 2030 |
| threatfox_export_json | 1917 |
| spamhaus_drop | 1665 |
| cisa_kev | 1656 |
| tor_exit_nodes | 1386 |
| malwarebazaar_recent | 702 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2318 |
| sha256 | 2117 |
| domain | 2013 |
| ipv4_cidr | 1665 |
| ipv4 | 677 |
| url | 556 |
| md5 | 292 |
| sha1 | 265 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3283 |
| malware | 2348 |
| cve | 2318 |
| drop | 1665 |
| spamhaus | 1665 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1559 |
| etherhiding | 1518 |
| nvd | 684 |
| c2 | 589 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 192[.]142[.]28[.]77 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 116[.]99[.]49[.]208 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]49 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]54 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 195[.]178[.]110[.]137 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 45[.]198[.]224[.]26 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 77[.]90[.]185[.]20 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 118[.]216[.]88[.]229 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
