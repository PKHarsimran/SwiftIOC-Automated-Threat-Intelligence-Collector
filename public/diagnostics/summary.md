# SwiftIOC IOC Summary

_Generated 2026-11-22T12:13:28Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-22T12:13:28Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2804 |
| Sources reporting | 16 |
| Indicator types | 9 |
| Multi-group overlaps | 468 |
| Score (min / avg / max) | 78 / 80.4 / 96 |
| High-score indicators (≥80) | 9990 |
| 2+ reporting groups | 468 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-22T12:13:14Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]163` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4681 |
| ipsum_level5 | 3261 |
| urlhaus_recent_urls | 1932 |
| nist_nvd_recent | 1824 |
| cisa_kev | 1790 |
| greensnow_blocklist | 1772 |
| spamhaus_drop | 1752 |
| malwarebazaar_recent | 1344 |
| tor_exit_nodes | 1252 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3959 |
| url | 1932 |
| sha256 | 1917 |
| ipv4_cidr | 1751 |
| md5 | 151 |
| sha1 | 151 |
| ja3 | 97 |
| ipv4 | 32 |
| domain | 10 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3959 |
| malware | 3677 |
| nvd | 2595 |
| malware_download | 1932 |
| exploited-in-the-wild | 1790 |
| drop | 1751 |
| spamhaus | 1751 |
| github | 1318 |
| threatfox | 1087 |
| js | 966 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 109[.]160[.]32[.]110 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]94[.]92[.]179 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 181[.]215[.]115[.]186 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
