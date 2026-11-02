# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-02T04:01:14Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-02T04:01:14Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7228 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 426 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 426 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-02T03:59:59Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5128 |
| ipsum_level5 | 4418 |
| greensnow_blocklist | 3912 |
| threatfox_export_json | 3668 |
| cisa_kev | 1766 |
| spamhaus_drop | 1754 |
| urlhaus_recent_urls | 1556 |
| tor_exit_nodes | 1237 |
| binarydefense_banlist | 1052 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2515 |
| url | 1925 |
| sha256 | 1848 |
| ipv4_cidr | 1753 |
| domain | 1352 |
| ipv4 | 287 |
| md5 | 160 |
| sha1 | 160 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3507 |
| malware | 2712 |
| cve | 2515 |
| exploited-in-the-wild | 1766 |
| drop | 1753 |
| spamhaus | 1753 |
| malware_download | 1560 |
| ClickFix | 1262 |
| nvd | 1148 |
| github | 933 |

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
