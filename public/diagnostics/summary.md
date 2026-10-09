# SwiftIOC IOC Summary

_Generated 2026-10-09T14:56:56Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-09T14:56:56Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6646 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 363 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 363 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-09T14:54:08Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `36[.]50[.]134[.]86` | score 96, 3 reporting groups |
| ipv4: `45[.]17[.]39[.]120` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 4686 |
| nist_nvd_recent | 4600 |
| greensnow_blocklist | 4537 |
| blocklist_de_ssh | 4487 |
| binarydefense_banlist | 2809 |
| threatfox_export_json | 2012 |
| cisa_kev | 1739 |
| spamhaus_drop | 1682 |
| urlhaus_recent_urls | 1665 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3408 |
| url | 1931 |
| ipv4_cidr | 1681 |
| sha256 | 1602 |
| domain | 764 |
| ipv4 | 234 |
| md5 | 190 |
| sha1 | 190 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3408 |
| malware | 3044 |
| threatfox | 2148 |
| nvd | 2009 |
| exploited-in-the-wild | 1739 |
| drop | 1681 |
| spamhaus | 1681 |
| malware_download | 1668 |
| CheatSheet | 1061 |
| exe | 834 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
