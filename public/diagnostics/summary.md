# SwiftIOC IOC Summary

_Generated 2026-10-21T03:01:47Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-21T03:01:47Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7509 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-group overlaps | 393 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 393 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-21T03:01:07Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5506 |
| blocklist_de_ssh | 5376 |
| ipsum_level5 | 5316 |
| threatfox_export_json | 3025 |
| cisa_kev | 1754 |
| spamhaus_drop | 1687 |
| malwarebazaar_recent | 1542 |
| tor_exit_nodes | 1208 |
| urlhaus_recent_urls | 678 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3144 |
| sha256 | 2728 |
| ipv4_cidr | 1661 |
| url | 1641 |
| domain | 321 |
| ipv4 | 247 |
| md5 | 130 |
| sha1 | 128 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3222 |
| cve | 3144 |
| malware | 2802 |
| nvd | 1756 |
| exploited-in-the-wild | 1754 |
| drop | 1661 |
| spamhaus | 1661 |
| Mirai | 763 |
| malware_download | 685 |
| vidar | 635 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 156[.]225[.]17[.]60 | binarydefense_banlist, ci_army_list, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
