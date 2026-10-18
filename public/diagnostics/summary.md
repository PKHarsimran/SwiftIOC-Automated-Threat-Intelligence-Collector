# SwiftIOC IOC Summary

_Generated 2026-10-18T15:16:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-18T15:16:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5787 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-group overlaps | 386 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 386 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-18T15:16:11Z |

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
| ipsum_level5 | 4946 |
| blocklist_de_ssh | 4413 |
| greensnow_blocklist | 3746 |
| threatfox_export_json | 2715 |
| nist_nvd_recent | 2600 |
| cisa_kev | 1748 |
| spamhaus_drop | 1692 |
| tor_exit_nodes | 1209 |
| malwarebazaar_recent | 914 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3364 |
| sha256 | 2742 |
| ipv4_cidr | 1691 |
| url | 1149 |
| domain | 495 |
| ipv4 | 216 |
| md5 | 171 |
| sha1 | 171 |
| ja3 | 1 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3479 |
| cve | 3364 |
| nvd | 1972 |
| malware | 1938 |
| exploited-in-the-wild | 1748 |
| drop | 1691 |
| spamhaus | 1691 |
| elf | 1257 |
| Mirai | 1067 |
| ClickFix | 740 |

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
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
