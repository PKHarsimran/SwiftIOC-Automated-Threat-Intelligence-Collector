# SwiftIOC IOC Summary

_Generated 2026-10-20T22:53:40Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-20T22:53:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7357 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 393 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 393 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-20T22:53:22Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5407 |
| blocklist_de_ssh | 5350 |
| greensnow_blocklist | 4729 |
| threatfox_export_json | 2867 |
| nist_nvd_recent | 2000 |
| cisa_kev | 1754 |
| spamhaus_drop | 1687 |
| binarydefense_banlist | 1465 |
| malwarebazaar_recent | 1435 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3144 |
| sha256 | 2789 |
| url | 1648 |
| ipv4_cidr | 1588 |
| ipv4 | 235 |
| domain | 232 |
| md5 | 183 |
| sha1 | 181 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3224 |
| cve | 3144 |
| malware | 2875 |
| nvd | 1756 |
| exploited-in-the-wild | 1754 |
| drop | 1588 |
| spamhaus | 1588 |
| Mirai | 815 |
| malware_download | 706 |
| vidar | 634 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 156[.]225[.]17[.]60 | binarydefense_banlist, ci_army_list, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
