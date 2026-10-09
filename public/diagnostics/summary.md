# SwiftIOC IOC Summary

_Generated 2026-10-09T04:16:55Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-09T04:16:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7494 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 363 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 363 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-09T04:05:03Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]60` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `45[.]17[.]39[.]120` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 88, 2 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5440 |
| ipsum_level5 | 4686 |
| blocklist_de_ssh | 4641 |
| binarydefense_banlist | 2809 |
| threatfox_export_json | 2034 |
| urlhaus_recent_urls | 2029 |
| cisa_kev | 1739 |
| spamhaus_drop | 1672 |
| tor_exit_nodes | 1218 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3127 |
| url | 2289 |
| ipv4_cidr | 1671 |
| sha256 | 1484 |
| domain | 778 |
| ipv4 | 271 |
| md5 | 190 |
| sha1 | 190 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3304 |
| cve | 3127 |
| threatfox | 2158 |
| malware_download | 2030 |
| exploited-in-the-wild | 1739 |
| nvd | 1727 |
| drop | 1671 |
| spamhaus | 1671 |
| CheatSheet | 1331 |
| exe | 937 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
