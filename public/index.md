# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-02T12:13:37Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-02T12:13:37Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6648 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 426 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 426 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-02T12:11:17Z |

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
| blocklist_de_ssh | 5060 |
| ipsum_level5 | 4418 |
| threatfox_export_json | 3675 |
| greensnow_blocklist | 3342 |
| cisa_kev | 1766 |
| spamhaus_drop | 1754 |
| urlhaus_recent_urls | 1278 |
| tor_exit_nodes | 1238 |
| binarydefense_banlist | 1052 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2457 |
| sha256 | 2115 |
| ipv4_cidr | 1734 |
| url | 1614 |
| domain | 1507 |
| ipv4 | 253 |
| md5 | 160 |
| sha1 | 160 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3741 |
| malware | 2618 |
| cve | 2457 |
| exploited-in-the-wild | 1766 |
| drop | 1734 |
| spamhaus | 1734 |
| ClickFix | 1313 |
| malware_download | 1281 |
| nvd | 1090 |
| github | 813 |

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
