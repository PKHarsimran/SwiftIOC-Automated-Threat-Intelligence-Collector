# SwiftIOC IOC Summary

_Generated 2026-10-14T03:15:47Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-14T03:15:47Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7948 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 374 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 374 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-14T03:14:57Z |

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
| greensnow_blocklist | 5680 |
| ipsum_level5 | 4558 |
| blocklist_de_ssh | 4185 |
| binarydefense_banlist | 4182 |
| threatfox_export_json | 3349 |
| nist_nvd_recent | 2800 |
| cisa_kev | 1741 |
| spamhaus_drop | 1682 |
| tor_exit_nodes | 1214 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3457 |
| url | 2637 |
| sha256 | 1752 |
| ipv4_cidr | 866 |
| domain | 555 |
| ipv4 | 307 |
| md5 | 213 |
| sha1 | 213 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3509 |
| cve | 3457 |
| malware | 2787 |
| nvd | 2059 |
| exploited-in-the-wild | 1741 |
| malware_download | 1120 |
| c2 | 974 |
| Vidar | 965 |
| stealer | 941 |
| loader | 938 |

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
