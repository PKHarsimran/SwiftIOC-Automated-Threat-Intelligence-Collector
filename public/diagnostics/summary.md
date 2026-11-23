# SwiftIOC IOC Summary

_Generated 2026-11-23T19:45:26Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-23T19:45:26Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4272 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 469 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 469 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-23T19:45:01Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]181` | score 96, 5 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]163` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 5559 |
| blocklist_de_ssh | 4763 |
| greensnow_blocklist | 2828 |
| ipsum_level5 | 2609 |
| nist_nvd_recent | 2178 |
| cisa_kev | 1790 |
| spamhaus_drop | 1752 |
| malwarebazaar_recent | 1499 |
| tor_exit_nodes | 1253 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2828 |
| sha256 | 2305 |
| ipv4 | 1960 |
| ipv4_cidr | 1209 |
| url | 923 |
| domain | 460 |
| sha1 | 160 |
| md5 | 155 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4317 |
| malware | 3029 |
| cve | 2828 |
| exploited-in-the-wild | 1790 |
| offensive-agency | 1485 |
| nvd | 1464 |
| elf | 1252 |
| drop | 1209 |
| spamhaus | 1209 |
| ARTEX | 1089 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]181 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]110 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]94[.]92[.]179 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]163 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
