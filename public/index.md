# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-15T22:51:30Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-15T22:51:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5104 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 381 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 381 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-15T22:44:25Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `103[.]170[.]217[.]170` | score 96, 3 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `165[.]245[.]160[.]178` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `36[.]50[.]134[.]86` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 4416 |
| greensnow_blocklist | 4344 |
| blocklist_de_ssh | 4161 |
| threatfox_export_json | 4070 |
| nist_nvd_recent | 2600 |
| cisa_kev | 1746 |
| spamhaus_drop | 1680 |
| tor_exit_nodes | 1212 |
| malwarebazaar_recent | 1015 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3155 |
| url | 2456 |
| ipv4_cidr | 1679 |
| sha256 | 1491 |
| domain | 553 |
| ipv4 | 298 |
| md5 | 184 |
| sha1 | 184 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3943 |
| cve | 3155 |
| nvd | 1762 |
| exploited-in-the-wild | 1746 |
| drop | 1679 |
| spamhaus | 1679 |
| c2 | 1536 |
| malware | 1467 |
| stealer | 1442 |
| Vidar | 1421 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]170[.]217[.]170 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]160[.]178 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]171[.]220 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
