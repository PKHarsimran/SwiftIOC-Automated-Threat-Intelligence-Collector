# SwiftIOC IOC Summary

_Generated 2026-11-06T23:56:02Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-06T23:56:02Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5759 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 425 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 425 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-06T23:55:03Z |

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
| ipsum_level5 | 4654 |
| blocklist_de_ssh | 4639 |
| threatfox_export_json | 3267 |
| greensnow_blocklist | 3045 |
| nist_nvd_recent | 2200 |
| cisa_kev | 1769 |
| spamhaus_drop | 1764 |
| tor_exit_nodes | 1246 |
| malwarebazaar_recent | 1109 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3416 |
| cve | 2716 |
| ipv4_cidr | 1763 |
| url | 963 |
| domain | 377 |
| ipv4 | 279 |
| md5 | 243 |
| sha1 | 243 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3574 |
| cve | 2716 |
| malware | 2507 |
| exploited-in-the-wild | 1769 |
| drop | 1763 |
| spamhaus | 1763 |
| nvd | 1351 |
| ClickFix | 995 |
| macOS | 982 |
| Amos | 944 |

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
