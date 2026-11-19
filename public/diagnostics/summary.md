# SwiftIOC IOC Summary

_Generated 2026-11-19T01:37:59Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-19T01:37:59Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4122 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 452 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 452 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-19T01:37:42Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `45[.]90[.]163[.]37` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 93, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5723 |
| ipsum_level5 | 3629 |
| nist_nvd_recent | 2400 |
| threatfox_export_json | 2270 |
| greensnow_blocklist | 2182 |
| cisa_kev | 1786 |
| spamhaus_drop | 1747 |
| urlhaus_recent_urls | 1461 |
| tor_exit_nodes | 1296 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3490 |
| sha256 | 2090 |
| url | 1542 |
| ipv4_cidr | 1121 |
| domain | 727 |
| ipv4 | 466 |
| md5 | 282 |
| sha1 | 282 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3490 |
| malware | 3435 |
| threatfox | 2718 |
| nvd | 2126 |
| exploited-in-the-wild | 1786 |
| malware_download | 1465 |
| drop | 1121 |
| spamhaus | 1121 |
| github | 908 |
| high | 734 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 181[.]215[.]115[.]186 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]110 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
