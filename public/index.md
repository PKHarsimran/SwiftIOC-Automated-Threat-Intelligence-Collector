# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-16T17:49:49Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-16T17:49:49Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3237 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 442 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 442 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-16T17:47:54Z |

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
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 91, 3 reporting groups |
| ipv4: `109[.]160[.]32[.]110` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4284 |
| threatfox_export_json | 3156 |
| ipsum_level5 | 2773 |
| cisa_kev | 1781 |
| spamhaus_drop | 1736 |
| tor_exit_nodes | 1266 |
| binarydefense_banlist | 1099 |
| malwarebazaar_recent | 1023 |
| greensnow_blocklist | 934 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2973 |
| sha256 | 2266 |
| ipv4_cidr | 1720 |
| url | 1162 |
| domain | 884 |
| ipv4 | 427 |
| md5 | 284 |
| sha1 | 284 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3105 |
| cve | 2973 |
| malware | 2905 |
| exploited-in-the-wild | 1781 |
| drop | 1720 |
| spamhaus | 1720 |
| nvd | 1609 |
| malware_download | 919 |
| Mirai | 818 |
| None | 635 |

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
