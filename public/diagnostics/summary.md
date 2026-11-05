# SwiftIOC IOC Summary

_Generated 2026-11-05T04:52:01Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-05T04:52:01Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5951 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 427 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 427 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-05T04:44:50Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4695 |
| ipsum_level5 | 4268 |
| nist_nvd_recent | 3800 |
| greensnow_blocklist | 3640 |
| threatfox_export_json | 2941 |
| urlhaus_recent_urls | 1955 |
| cisa_kev | 1768 |
| spamhaus_drop | 1763 |
| tor_exit_nodes | 1239 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2787 |
| url | 2539 |
| sha256 | 1797 |
| ipv4_cidr | 1762 |
| domain | 535 |
| ipv4 | 258 |
| md5 | 161 |
| sha1 | 161 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 2982 |
| cve | 2787 |
| threatfox | 2765 |
| malware_download | 1955 |
| exploited-in-the-wild | 1768 |
| drop | 1762 |
| spamhaus | 1762 |
| github | 1453 |
| nvd | 1422 |
| zapret | 1300 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 180[.]93[.]193[.]100 | ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
