# SwiftIOC IOC Summary

_Generated 2026-11-18T16:54:28Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-18T16:54:28Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4449 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 447 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 447 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-18T16:53:18Z |

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
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5253 |
| ipsum_level5 | 3629 |
| threatfox_export_json | 2610 |
| nist_nvd_recent | 2200 |
| greensnow_blocklist | 1810 |
| cisa_kev | 1782 |
| binarydefense_banlist | 1774 |
| spamhaus_drop | 1747 |
| urlhaus_recent_urls | 1422 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3078 |
| sha256 | 1953 |
| url | 1499 |
| ipv4_cidr | 1343 |
| domain | 1124 |
| ipv4 | 439 |
| md5 | 282 |
| sha1 | 282 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3254 |
| cve | 3078 |
| threatfox | 3076 |
| exploited-in-the-wild | 1782 |
| nvd | 1714 |
| malware_download | 1423 |
| drop | 1343 |
| spamhaus | 1343 |
| github | 811 |
| Mirai | 693 |

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
