# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-16T04:28:12Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-16T04:28:12Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2944 |
| Sources reporting | 14 |
| Indicator types | 8 |
| Multi-group overlaps | 443 |
| Score (min / avg / max) | 79 / 80.4 / 96 |
| High-score indicators (≥80) | 9930 |
| 2+ reporting groups | 443 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-16T04:19:57Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `45[.]90[.]163[.]37` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4658 |
| ipsum_level5 | 2773 |
| threatfox_export_json | 2665 |
| cisa_kev | 1781 |
| spamhaus_drop | 1759 |
| tor_exit_nodes | 1260 |
| urlhaus_recent_urls | 1178 |
| malwarebazaar_recent | 1138 |
| binarydefense_banlist | 1099 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2978 |
| sha256 | 2214 |
| ipv4_cidr | 1758 |
| url | 1388 |
| domain | 913 |
| md5 | 285 |
| sha1 | 285 |
| ipv4 | 179 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3081 |
| cve | 2978 |
| threatfox | 2901 |
| exploited-in-the-wild | 1781 |
| drop | 1758 |
| spamhaus | 1758 |
| nvd | 1614 |
| malware_download | 1178 |
| Mirai | 851 |
| high | 656 |

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
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
