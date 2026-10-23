# SwiftIOC IOC Summary

_Generated 2026-10-23T22:52:00Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-23T22:52:00Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6675 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-group overlaps | 399 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 399 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-23T22:41:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 13781 |
| ipsum_level5 | 5475 |
| blocklist_de_ssh | 4896 |
| greensnow_blocklist | 4558 |
| nist_nvd_recent | 4200 |
| threatfox_export_json | 3287 |
| cisa_kev | 1756 |
| spamhaus_drop | 1688 |
| tor_exit_nodes | 1218 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5670 |
| cve | 1756 |
| ipv4_cidr | 1687 |
| sha256 | 490 |
| domain | 161 |
| ipv4 | 131 |
| md5 | 53 |
| sha1 | 52 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 5798 |
| malware_download | 5525 |
| zip | 5344 |
| github | 5336 |
| SmartLoader | 5215 |
| cve | 1756 |
| exploited-in-the-wild | 1756 |
| drop | 1687 |
| spamhaus | 1687 |
| threatfox | 817 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
