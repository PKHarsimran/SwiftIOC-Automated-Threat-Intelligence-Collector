# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-13T00:51:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-13T00:51:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4442 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 437 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 437 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-13T00:51:00Z |

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
| ipv4: `181[.]215[.]115[.]186` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4521 |
| ipsum_level5 | 3708 |
| greensnow_blocklist | 3272 |
| threatfox_export_json | 3245 |
| nist_nvd_recent | 2800 |
| cisa_kev | 1779 |
| spamhaus_drop | 1758 |
| tor_exit_nodes | 1257 |
| urlhaus_recent_urls | 1159 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2791 |
| cve | 2388 |
| ipv4_cidr | 1757 |
| url | 1291 |
| domain | 1186 |
| md5 | 219 |
| sha1 | 212 |
| ipv4 | 156 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3358 |
| malware | 3312 |
| cve | 2388 |
| exploited-in-the-wild | 1779 |
| drop | 1757 |
| spamhaus | 1757 |
| malware_download | 1170 |
| nvd | 1024 |
| None | 701 |
| Mirai | 664 |

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
