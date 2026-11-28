# SwiftIOC IOC Summary

_Generated 2026-11-28T05:59:15Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-28T05:59:15Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4561 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 496 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 496 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-28T05:48:09Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `103[.]248[.]120[.]6` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]131` | score 96, 4 reporting groups |
| ipv4: `211[.]230[.]3[.]71` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `115[.]191[.]79[.]153` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `185[.]226[.]93[.]242` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4228 |
| threatfox_export_json | 3981 |
| ipsum_level5 | 3084 |
| greensnow_blocklist | 2617 |
| cisa_kev | 1808 |
| spamhaus_drop | 1737 |
| nist_nvd_recent | 1398 |
| urlhaus_recent_urls | 1354 |
| binarydefense_banlist | 1283 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2934 |
| ipv4_cidr | 1736 |
| url | 1485 |
| ipv4 | 1436 |
| sha256 | 1359 |
| domain | 576 |
| md5 | 237 |
| sha1 | 237 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3274 |
| cve | 2934 |
| malware | 2461 |
| exploited-in-the-wild | 1808 |
| drop | 1736 |
| spamhaus | 1736 |
| nvd | 1570 |
| malware_download | 1368 |
| offensive-agency | 1075 |
| ARTEX | 959 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]181 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]248[.]120[.]6 | blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]110 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]131 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 211[.]230[.]3[.]71 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]94[.]92[.]179 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]163 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
