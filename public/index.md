# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-27T02:36:39Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-27T02:36:39Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4281 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 481 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 481 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-27T02:36:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]181` | score 96, 5 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]131` | score 96, 4 reporting groups |
| ipv4: `211[.]230[.]3[.]71` | score 96, 4 reporting groups |
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
| blocklist_de_ssh | 4457 |
| threatfox_export_json | 4141 |
| ipsum_level5 | 2990 |
| greensnow_blocklist | 2735 |
| nist_nvd_recent | 2274 |
| cisa_kev | 1805 |
| spamhaus_drop | 1737 |
| tor_exit_nodes | 1264 |
| malwarebazaar_recent | 1064 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3278 |
| sha256 | 1479 |
| ipv4_cidr | 1365 |
| ipv4 | 1245 |
| domain | 1238 |
| url | 1027 |
| md5 | 184 |
| sha1 | 184 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3953 |
| cve | 3278 |
| malware | 1918 |
| nvd | 1914 |
| exploited-in-the-wild | 1805 |
| drop | 1365 |
| spamhaus | 1365 |
| offensive-agency | 767 |
| medium | 716 |
| malware_download | 698 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]181 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]110 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]131 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 211[.]230[.]3[.]71 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]94[.]92[.]179 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]163 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
