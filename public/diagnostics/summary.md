# SwiftIOC IOC Summary

_Generated 2026-11-10T12:02:23Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-10T12:02:23Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4905 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 432 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 432 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-10T12:01:14Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 92, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4400 |
| ipsum_level5 | 3552 |
| greensnow_blocklist | 2692 |
| malwarebazaar_recent | 2249 |
| nist_nvd_recent | 2200 |
| threatfox_export_json | 2094 |
| cisa_kev | 1773 |
| spamhaus_drop | 1764 |
| urlhaus_recent_urls | 1251 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3042 |
| cve | 2817 |
| ipv4_cidr | 1763 |
| url | 1386 |
| domain | 401 |
| md5 | 218 |
| sha1 | 218 |
| ipv4 | 155 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4034 |
| cve | 2817 |
| threatfox | 2504 |
| exploited-in-the-wild | 1773 |
| drop | 1763 |
| spamhaus | 1763 |
| nvd | 1454 |
| malware_download | 1251 |
| elf | 1124 |
| Mirai | 757 |

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
