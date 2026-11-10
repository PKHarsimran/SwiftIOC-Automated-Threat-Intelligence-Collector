# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-10T21:37:30Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-10T21:37:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4710 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 437 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 437 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-10T21:33:12Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 92, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 89, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4450 |
| ipsum_level5 | 3552 |
| greensnow_blocklist | 2823 |
| nist_nvd_recent | 2400 |
| malwarebazaar_recent | 2331 |
| threatfox_export_json | 2020 |
| cisa_kev | 1779 |
| spamhaus_drop | 1764 |
| tor_exit_nodes | 1253 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3076 |
| sha256 | 2956 |
| ipv4_cidr | 1763 |
| url | 1266 |
| domain | 384 |
| md5 | 200 |
| sha1 | 200 |
| ipv4 | 155 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4013 |
| cve | 3076 |
| threatfox | 2306 |
| exploited-in-the-wild | 1779 |
| drop | 1763 |
| spamhaus | 1763 |
| nvd | 1712 |
| malware_download | 1129 |
| elf | 1084 |
| Mirai | 712 |

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
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
