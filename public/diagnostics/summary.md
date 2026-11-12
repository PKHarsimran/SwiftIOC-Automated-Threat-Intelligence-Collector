# SwiftIOC IOC Summary

_Generated 2026-11-12T16:31:30Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-12T16:31:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4603 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-group overlaps | 436 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 436 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-12T16:30:29Z |

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
| blocklist_de_ssh | 4476 |
| ipsum_level5 | 3708 |
| threatfox_export_json | 2727 |
| greensnow_blocklist | 2714 |
| cisa_kev | 1779 |
| spamhaus_drop | 1756 |
| urlhaus_recent_urls | 1297 |
| tor_exit_nodes | 1258 |
| malwarebazaar_recent | 1120 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3166 |
| cve | 2307 |
| ipv4_cidr | 1725 |
| url | 1424 |
| domain | 933 |
| ipv4 | 156 |
| md5 | 148 |
| sha1 | 141 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3817 |
| threatfox | 2897 |
| cve | 2307 |
| exploited-in-the-wild | 1779 |
| drop | 1725 |
| spamhaus | 1725 |
| malware_download | 1307 |
| nvd | 943 |
| None | 805 |
| elf | 677 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2010-0188 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
