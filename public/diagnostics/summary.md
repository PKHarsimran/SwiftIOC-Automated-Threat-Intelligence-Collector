# SwiftIOC IOC Summary

_Generated 2026-11-07T19:49:49Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-07T19:49:49Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5827 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 428 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 428 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-07T19:46:18Z |

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
| ipv4: `158[.]220[.]81[.]103` | score 88, 2 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4510 |
| ipsum_level5 | 4471 |
| threatfox_export_json | 2888 |
| greensnow_blocklist | 2812 |
| nist_nvd_recent | 2400 |
| cisa_kev | 1769 |
| spamhaus_drop | 1764 |
| binarydefense_banlist | 1332 |
| tor_exit_nodes | 1245 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3578 |
| cve | 2357 |
| ipv4_cidr | 1763 |
| url | 1119 |
| md5 | 330 |
| sha1 | 330 |
| ipv4 | 265 |
| domain | 258 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3837 |
| malware | 2806 |
| cve | 2357 |
| exploited-in-the-wild | 1769 |
| drop | 1763 |
| spamhaus | 1763 |
| macOS | 1096 |
| ClickFix | 1068 |
| Amos | 1035 |
| Foxveil | 1034 |

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
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
