# SwiftIOC IOC Summary

_Generated 2026-10-16T15:57:55Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-16T15:57:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5552 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 382 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 382 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-16T15:57:34Z |

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
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 4457 |
| threatfox_export_json | 4410 |
| greensnow_blocklist | 4285 |
| blocklist_de_ssh | 4268 |
| nist_nvd_recent | 2200 |
| cisa_kev | 1746 |
| spamhaus_drop | 1691 |
| tor_exit_nodes | 1207 |
| malwarebazaar_recent | 796 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2624 |
| url | 2520 |
| sha256 | 1966 |
| ipv4_cidr | 1667 |
| domain | 437 |
| ipv4 | 336 |
| md5 | 225 |
| sha1 | 225 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4338 |
| cve | 2624 |
| exploited-in-the-wild | 1746 |
| malware | 1684 |
| drop | 1667 |
| spamhaus | 1667 |
| c2 | 1495 |
| stealer | 1407 |
| Vidar | 1405 |
| loader | 1390 |

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
