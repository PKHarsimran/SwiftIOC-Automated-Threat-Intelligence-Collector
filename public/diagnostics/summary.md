# SwiftIOC IOC Summary

_Generated 2026-11-14T17:35:49Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-14T17:35:49Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3991 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 441 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 441 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-14T17:25:29Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 93, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4838 |
| ipsum_level5 | 3322 |
| greensnow_blocklist | 2659 |
| threatfox_export_json | 2653 |
| cisa_kev | 1781 |
| spamhaus_drop | 1759 |
| tor_exit_nodes | 1259 |
| malwarebazaar_recent | 1085 |
| urlhaus_recent_urls | 906 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3122 |
| sha256 | 2416 |
| ipv4_cidr | 1758 |
| domain | 1255 |
| url | 1016 |
| ipv4 | 158 |
| md5 | 141 |
| sha1 | 134 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3122 |
| threatfox | 2866 |
| malware | 2777 |
| exploited-in-the-wild | 1781 |
| nvd | 1758 |
| drop | 1758 |
| spamhaus | 1758 |
| malware_download | 912 |
| etherhiding | 847 |
| high | 745 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 120[.]193[.]9[.]169 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 181[.]215[.]115[.]186 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
