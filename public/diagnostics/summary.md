# SwiftIOC IOC Summary

_Generated 2026-11-20T16:37:47Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-20T16:37:47Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3130 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 456 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 456 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-20T16:37:30Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `78[.]128[.]114[.]166` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 92, 4 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 92, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5696 |
| ipsum_level5 | 3151 |
| nist_nvd_recent | 2600 |
| threatfox_export_json | 2021 |
| greensnow_blocklist | 1913 |
| cisa_kev | 1786 |
| spamhaus_drop | 1747 |
| urlhaus_recent_urls | 1740 |
| malwarebazaar_recent | 1385 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3196 |
| sha256 | 2070 |
| url | 1947 |
| ipv4_cidr | 1746 |
| ipv4 | 451 |
| domain | 350 |
| md5 | 120 |
| sha1 | 120 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3531 |
| cve | 3196 |
| threatfox | 2005 |
| nvd | 1832 |
| malware_download | 1817 |
| exploited-in-the-wild | 1786 |
| drop | 1746 |
| spamhaus | 1746 |
| github | 1267 |
| js | 998 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 181[.]215[.]115[.]186 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
