# SwiftIOC IOC Summary

_Generated 2026-11-24T19:17:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-24T19:17:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4454 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 474 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 474 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-24T19:16:43Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]181` | score 96, 5 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `211[.]230[.]3[.]71` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]163` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 7882 |
| blocklist_de_ssh | 4797 |
| nist_nvd_recent | 3000 |
| greensnow_blocklist | 2814 |
| ipsum_level5 | 2398 |
| cisa_kev | 1795 |
| spamhaus_drop | 1737 |
| malwarebazaar_recent | 1670 |
| tor_exit_nodes | 1251 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4288 |
| cve | 1978 |
| ipv4_cidr | 1736 |
| sha256 | 950 |
| url | 671 |
| domain | 177 |
| md5 | 100 |
| sha1 | 100 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 5110 |
| offensive-agency | 4137 |
| ARTEX | 3108 |
| cve | 1978 |
| exploited-in-the-wild | 1795 |
| drop | 1736 |
| spamhaus | 1736 |
| malware | 1503 |
| CyberStrikeAI | 698 |
| malware_download | 637 |

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
