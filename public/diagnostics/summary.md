# SwiftIOC IOC Summary

_Generated 2026-11-24T04:33:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-24T04:33:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4571 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 473 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 473 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-24T04:33:30Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]181` | score 96, 5 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `211[.]230[.]3[.]71` | score 96, 4 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]163` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 8373 |
| blocklist_de_ssh | 4314 |
| greensnow_blocklist | 3149 |
| nist_nvd_recent | 2598 |
| ipsum_level5 | 2398 |
| cisa_kev | 1792 |
| spamhaus_drop | 1752 |
| malwarebazaar_recent | 1331 |
| tor_exit_nodes | 1251 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4490 |
| cve | 2378 |
| sha256 | 1240 |
| url | 722 |
| ipv4_cidr | 557 |
| domain | 298 |
| sha1 | 160 |
| md5 | 155 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 5974 |
| offensive-agency | 4161 |
| ARTEX | 3243 |
| cve | 2378 |
| exploited-in-the-wild | 1792 |
| malware | 1780 |
| nvd | 1014 |
| CyberStrikeAI | 762 |
| elf | 678 |
| malware_download | 657 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]181 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]110 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 211[.]230[.]3[.]71 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]94[.]92[.]179 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]163 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
