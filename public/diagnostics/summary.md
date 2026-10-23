# SwiftIOC IOC Summary

_Generated 2026-10-23T16:20:04Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-23T16:20:04Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6623 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 397 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 397 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-23T16:19:27Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 12060 |
| ipsum_level5 | 5475 |
| blocklist_de_ssh | 4984 |
| greensnow_blocklist | 4587 |
| threatfox_export_json | 3605 |
| nist_nvd_recent | 3000 |
| cisa_kev | 1754 |
| spamhaus_drop | 1688 |
| malwarebazaar_recent | 1301 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5919 |
| cve | 1754 |
| ipv4_cidr | 1688 |
| sha256 | 329 |
| domain | 105 |
| ipv4 | 101 |
| md5 | 52 |
| sha1 | 52 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 5964 |
| malware_download | 5780 |
| zip | 5620 |
| github | 5617 |
| SmartLoader | 5224 |
| cve | 1754 |
| exploited-in-the-wild | 1754 |
| drop | 1688 |
| spamhaus | 1688 |
| threatfox | 633 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
