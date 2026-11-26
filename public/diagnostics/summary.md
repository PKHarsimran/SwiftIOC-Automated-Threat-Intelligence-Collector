# SwiftIOC IOC Summary

_Generated 2026-11-26T18:03:21Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-26T18:03:21Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3758 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 480 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 480 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-26T17:58:50Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `211[.]230[.]3[.]71` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]131` | score 96, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]163` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4538 |
| threatfox_export_json | 4040 |
| ipsum_level5 | 3000 |
| greensnow_blocklist | 2345 |
| nist_nvd_recent | 2200 |
| cisa_kev | 1805 |
| spamhaus_drop | 1737 |
| tor_exit_nodes | 1261 |
| malwarebazaar_recent | 1124 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3224 |
| sha256 | 1409 |
| ipv4 | 1351 |
| domain | 1218 |
| ipv4_cidr | 1200 |
| url | 1200 |
| md5 | 199 |
| sha1 | 199 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3935 |
| cve | 3224 |
| malware | 2132 |
| nvd | 1860 |
| exploited-in-the-wild | 1805 |
| drop | 1200 |
| spamhaus | 1200 |
| offensive-agency | 929 |
| malware_download | 880 |
| ARTEX | 728 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]181 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]110 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 211[.]230[.]3[.]71 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]94[.]92[.]179 | binarydefense_banlist, blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 109[.]160[.]32[.]163 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
