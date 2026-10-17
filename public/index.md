# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-17T08:12:44Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-17T08:12:44Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6283 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 385 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 385 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-17T08:12:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 3 reporting groups |
| ipv4: `165[.]245[.]160[.]178` | score 94, 3 reporting groups |
| ipv4: `165[.]245[.]171[.]220` | score 94, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5102 |
| greensnow_blocklist | 4973 |
| blocklist_de_ssh | 4471 |
| threatfox_export_json | 3978 |
| nist_nvd_recent | 3000 |
| cisa_kev | 1748 |
| spamhaus_drop | 1691 |
| tor_exit_nodes | 1208 |
| malwarebazaar_recent | 610 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3179 |
| sha256 | 2325 |
| url | 1850 |
| ipv4_cidr | 1690 |
| domain | 315 |
| ipv4 | 315 |
| md5 | 163 |
| sha1 | 163 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3974 |
| cve | 3179 |
| nvd | 1787 |
| exploited-in-the-wild | 1748 |
| drop | 1690 |
| spamhaus | 1690 |
| malware | 1504 |
| elf | 1131 |
| c2 | 1010 |
| Vidar | 934 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]170[.]217[.]170 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]160[.]178 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]171[.]220 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
