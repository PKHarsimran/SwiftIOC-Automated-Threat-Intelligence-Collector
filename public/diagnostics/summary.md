# SwiftIOC IOC Summary

_Generated 2026-10-17T18:06:56Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-17T18:06:56Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5653 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 386 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 386 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-17T18:03:21Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `130[.]12[.]180[.]32` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 95, 3 reporting groups |
| ipv4: `165[.]245[.]160[.]178` | score 90, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5102 |
| blocklist_de_ssh | 4477 |
| greensnow_blocklist | 4238 |
| threatfox_export_json | 3744 |
| nist_nvd_recent | 2600 |
| cisa_kev | 1748 |
| spamhaus_drop | 1692 |
| tor_exit_nodes | 1212 |
| malwarebazaar_recent | 810 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3122 |
| sha256 | 2408 |
| ipv4_cidr | 1683 |
| url | 1646 |
| domain | 411 |
| ipv4 | 298 |
| md5 | 216 |
| sha1 | 216 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4040 |
| cve | 3122 |
| exploited-in-the-wild | 1748 |
| nvd | 1730 |
| drop | 1683 |
| spamhaus | 1683 |
| malware | 1544 |
| elf | 1197 |
| Mirai | 953 |
| Vidar | 692 |

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
