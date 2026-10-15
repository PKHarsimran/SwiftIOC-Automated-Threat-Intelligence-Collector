# SwiftIOC IOC Summary

_Generated 2026-10-15T02:59:35Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-15T02:59:35Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6068 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 382 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 382 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-15T02:44:34Z |

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
| nist_nvd_recent | 8522 |
| greensnow_blocklist | 5577 |
| ipsum_level5 | 4416 |
| blocklist_de_ssh | 4124 |
| threatfox_export_json | 3926 |
| cisa_kev | 1745 |
| spamhaus_drop | 1682 |
| malwarebazaar_recent | 1254 |
| tor_exit_nodes | 1210 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4443 |
| url | 1871 |
| ipv4_cidr | 1677 |
| sha256 | 974 |
| domain | 606 |
| ipv4 | 179 |
| md5 | 125 |
| sha1 | 125 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4443 |
| nvd | 3051 |
| threatfox | 2811 |
| exploited-in-the-wild | 1745 |
| drop | 1677 |
| spamhaus | 1677 |
| high | 1640 |
| malware | 1248 |
| c2 | 1077 |
| stealer | 1051 |

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
