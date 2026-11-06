# SwiftIOC IOC Summary

_Generated 2026-11-06T00:41:23Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-06T00:41:23Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5679 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 427 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 427 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-06T00:35:29Z |

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
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4798 |
| ipsum_level5 | 4268 |
| greensnow_blocklist | 3653 |
| threatfox_export_json | 2738 |
| nist_nvd_recent | 2000 |
| cisa_kev | 1768 |
| spamhaus_drop | 1763 |
| tor_exit_nodes | 1240 |
| malwarebazaar_recent | 1083 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3337 |
| sha256 | 2566 |
| ipv4_cidr | 1762 |
| url | 1154 |
| domain | 490 |
| ipv4 | 235 |
| md5 | 228 |
| sha1 | 228 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3337 |
| threatfox | 3119 |
| malware | 2227 |
| nvd | 1973 |
| exploited-in-the-wild | 1768 |
| drop | 1762 |
| spamhaus | 1762 |
| ClickFix | 996 |
| macOS | 936 |
| Amos | 909 |

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
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
