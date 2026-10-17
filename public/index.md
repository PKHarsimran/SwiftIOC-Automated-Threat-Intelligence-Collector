# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-17T21:56:30Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-17T21:56:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5641 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-group overlaps | 386 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 386 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-17T21:56:12Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `130[.]12[.]180[.]32` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `85[.]215[.]45[.]36` | score 96, 3 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5102 |
| blocklist_de_ssh | 4482 |
| greensnow_blocklist | 4162 |
| threatfox_export_json | 3457 |
| nist_nvd_recent | 2200 |
| cisa_kev | 1748 |
| spamhaus_drop | 1692 |
| tor_exit_nodes | 1214 |
| malwarebazaar_recent | 802 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3122 |
| sha256 | 2484 |
| ipv4_cidr | 1691 |
| url | 1525 |
| domain | 478 |
| ipv4 | 267 |
| md5 | 216 |
| sha1 | 216 |
| ja3 | 1 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3987 |
| cve | 3122 |
| exploited-in-the-wild | 1748 |
| nvd | 1730 |
| drop | 1691 |
| spamhaus | 1691 |
| malware | 1593 |
| elf | 1216 |
| Mirai | 974 |
| ClickFix | 716 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 130[.]12[.]180[.]32 | blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]170[.]217[.]170 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]160[.]178 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]171[.]220 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
