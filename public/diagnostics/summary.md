# SwiftIOC IOC Summary

_Generated 2026-11-11T22:26:16Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-11T22:26:16Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4680 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 437 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 437 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-11T22:25:55Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4462 |
| ipsum_level5 | 3423 |
| nist_nvd_recent | 3200 |
| greensnow_blocklist | 2798 |
| threatfox_export_json | 2717 |
| cisa_kev | 1779 |
| spamhaus_drop | 1756 |
| malwarebazaar_recent | 1386 |
| urlhaus_recent_urls | 1313 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3371 |
| cve | 2473 |
| url | 1446 |
| ipv4_cidr | 1124 |
| domain | 869 |
| md5 | 272 |
| sha1 | 272 |
| ipv4 | 173 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4326 |
| threatfox | 3158 |
| cve | 2473 |
| exploited-in-the-wild | 1779 |
| malware_download | 1332 |
| drop | 1124 |
| spamhaus | 1124 |
| nvd | 1109 |
| elf | 961 |
| None | 750 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
