# SwiftIOC IOC Summary

_Generated 2026-11-17T12:42:40Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-17T12:42:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3944 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 445 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 445 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-17T12:42:28Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `45[.]90[.]163[.]37` | score 96, 4 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `109[.]160[.]32[.]136` | score 96, 3 reporting groups |
| ipv4: `120[.]193[.]9[.]169` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `181[.]215[.]115[.]186` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4824 |
| threatfox_export_json | 3008 |
| ipsum_level5 | 2802 |
| cisa_kev | 1781 |
| greensnow_blocklist | 1761 |
| spamhaus_drop | 1736 |
| nist_nvd_recent | 1577 |
| binarydefense_banlist | 1400 |
| tor_exit_nodes | 1270 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3191 |
| sha256 | 2043 |
| ipv4_cidr | 1735 |
| domain | 1175 |
| url | 950 |
| ipv4 | 464 |
| md5 | 221 |
| sha1 | 221 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3191 |
| threatfox | 3056 |
| malware | 2661 |
| nvd | 1827 |
| exploited-in-the-wild | 1781 |
| drop | 1735 |
| spamhaus | 1735 |
| Mirai | 765 |
| malware_download | 723 |
| high | 684 |

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
| ipv4: 109[.]160[.]32[.]136 | blocklist_de_ssh, greensnow_blocklist, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
