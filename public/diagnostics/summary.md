# SwiftIOC IOC Summary

_Generated 2026-11-01T17:31:59Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-01T17:31:59Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6582 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 425 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 425 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-01T17:24:43Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `176[.]123[.]7[.]7` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5066 |
| ipsum_level5 | 4662 |
| threatfox_export_json | 3751 |
| greensnow_blocklist | 3306 |
| cisa_kev | 1766 |
| spamhaus_drop | 1754 |
| urlhaus_recent_urls | 1732 |
| nist_nvd_recent | 1356 |
| tor_exit_nodes | 1234 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2403 |
| url | 2142 |
| ipv4_cidr | 1755 |
| sha256 | 1569 |
| domain | 1489 |
| ipv4 | 322 |
| md5 | 160 |
| sha1 | 160 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3468 |
| malware | 2795 |
| cve | 2403 |
| exploited-in-the-wild | 1766 |
| drop | 1755 |
| spamhaus | 1755 |
| malware_download | 1734 |
| ClickFix | 1518 |
| nvd | 1036 |
| github | 924 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 156[.]225[.]17[.]60 | binarydefense_banlist, ci_army_list, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
