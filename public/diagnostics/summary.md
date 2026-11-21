# SwiftIOC IOC Summary

_Generated 2026-11-21T12:00:14Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-21T12:00:14Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3204 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 465 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 465 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-21T11:59:56Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5722 |
| nist_nvd_recent | 3000 |
| ipsum_level5 | 2855 |
| threatfox_export_json | 2688 |
| urlhaus_recent_urls | 2017 |
| cisa_kev | 1790 |
| spamhaus_drop | 1751 |
| greensnow_blocklist | 1335 |
| tor_exit_nodes | 1298 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3322 |
| url | 2226 |
| sha256 | 1834 |
| ipv4_cidr | 1209 |
| domain | 629 |
| ipv4 | 412 |
| md5 | 184 |
| sha1 | 184 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3570 |
| cve | 3322 |
| threatfox | 2427 |
| malware_download | 2092 |
| nvd | 1958 |
| exploited-in-the-wild | 1790 |
| github | 1330 |
| drop | 1209 |
| spamhaus | 1209 |
| js | 1000 |

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
