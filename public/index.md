# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-22T00:03:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-22T00:03:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3588 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 468 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 468 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-22T00:01:48Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `78[.]128[.]114[.]166` | score 96, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 94, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5365 |
| threatfox_export_json | 3057 |
| ipsum_level5 | 2855 |
| greensnow_blocklist | 2305 |
| nist_nvd_recent | 2139 |
| urlhaus_recent_urls | 1948 |
| cisa_kev | 1790 |
| spamhaus_drop | 1752 |
| tor_exit_nodes | 1264 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3197 |
| url | 2067 |
| ipv4_cidr | 1553 |
| sha256 | 1463 |
| ipv4 | 713 |
| domain | 705 |
| md5 | 151 |
| sha1 | 151 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3242 |
| cve | 3197 |
| threatfox | 2574 |
| malware_download | 1951 |
| nvd | 1833 |
| exploited-in-the-wild | 1790 |
| drop | 1553 |
| spamhaus | 1553 |
| github | 1317 |
| js | 998 |

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
