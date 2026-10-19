# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-19T23:16:07Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-19T23:16:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6901 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-group overlaps | 383 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 383 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-19T23:05:48Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `130[.]12[.]180[.]32` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `194[.]238[.]29[.]124` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `85[.]215[.]45[.]36` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5306 |
| blocklist_de_ssh | 5267 |
| greensnow_blocklist | 5127 |
| threatfox_export_json | 2577 |
| nist_nvd_recent | 2200 |
| cisa_kev | 1748 |
| spamhaus_drop | 1693 |
| tor_exit_nodes | 1208 |
| malwarebazaar_recent | 1174 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3045 |
| cve | 2942 |
| ipv4_cidr | 1692 |
| url | 1244 |
| domain | 555 |
| ipv4 | 231 |
| md5 | 127 |
| sha1 | 125 |
| ja3 | 39 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3445 |
| cve | 2942 |
| malware | 2364 |
| exploited-in-the-wild | 1748 |
| drop | 1692 |
| spamhaus | 1692 |
| nvd | 1550 |
| Mirai | 1159 |
| elf | 1047 |
| ClickFix | 656 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 130[.]12[.]180[.]32 | blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 194[.]238[.]29[.]124 | blocklist_de_ssh, ci_army_list, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
