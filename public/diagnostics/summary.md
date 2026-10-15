# SwiftIOC IOC Summary

_Generated 2026-10-15T08:47:07Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-15T08:47:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5840 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 381 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 381 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-15T08:46:10Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `103[.]170[.]217[.]170` | score 96, 3 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `165[.]245[.]160[.]178` | score 96, 3 reporting groups |
| ipv4: `165[.]245[.]171[.]220` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `36[.]50[.]134[.]86` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5530 |
| ipsum_level5 | 4416 |
| threatfox_export_json | 4079 |
| blocklist_de_ssh | 4052 |
| nist_nvd_recent | 2000 |
| cisa_kev | 1745 |
| spamhaus_drop | 1682 |
| tor_exit_nodes | 1210 |
| malwarebazaar_recent | 1197 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4338 |
| url | 1980 |
| ipv4_cidr | 1681 |
| sha256 | 1015 |
| domain | 542 |
| ipv4 | 194 |
| md5 | 125 |
| sha1 | 125 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4338 |
| nvd | 2946 |
| threatfox | 2914 |
| exploited-in-the-wild | 1745 |
| drop | 1681 |
| spamhaus | 1681 |
| high | 1605 |
| malware | 1227 |
| c2 | 1174 |
| stealer | 1149 |

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
