# SwiftIOC IOC Summary

_Generated 2026-11-26T07:07:18Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-26T07:07:18Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3502 |
| Sources reporting | 16 |
| Indicator types | 7 |
| Multi-group overlaps | 478 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 478 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-26T07:00:06Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `109[.]160[.]32[.]110` | score 96, 4 reporting groups |
| ipv4: `211[.]230[.]3[.]71` | score 96, 4 reporting groups |
| ipv4: `80[.]94[.]92[.]179` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
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
| blocklist_de_ssh | 4608 |
| nist_nvd_recent | 3443 |
| ipsum_level5 | 3000 |
| greensnow_blocklist | 2705 |
| cisa_kev | 1805 |
| spamhaus_drop | 1737 |
| malwarebazaar_recent | 1511 |
| tor_exit_nodes | 1256 |
| urlhaus_recent_urls | 782 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 5306 |
| sha256 | 1950 |
| ipv4_cidr | 1736 |
| url | 782 |
| md5 | 100 |
| sha1 | 100 |
| ipv4 | 26 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 5306 |
| nvd | 3942 |
| malware | 2540 |
| exploited-in-the-wild | 1805 |
| drop | 1736 |
| spamhaus | 1736 |
| medium | 1566 |
| high | 1135 |
| threatfox | 945 |
| malware_download | 782 |

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
