# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-30T04:03:51Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-30T04:03:51Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7785 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-group overlaps | 425 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 425 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-30T04:01:01Z |

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
| urlhaus_recent_urls | 6838 |
| threatfox_export_json | 5683 |
| ipsum_level5 | 5012 |
| blocklist_de_ssh | 4878 |
| greensnow_blocklist | 4275 |
| cisa_kev | 1764 |
| spamhaus_drop | 1757 |
| tor_exit_nodes | 1225 |
| malwarebazaar_recent | 981 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 4001 |
| domain | 1907 |
| cve | 1764 |
| ipv4_cidr | 1416 |
| sha256 | 597 |
| ipv4 | 139 |
| md5 | 88 |
| sha1 | 88 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3909 |
| malware_download | 3565 |
| github | 3301 |
| SalatStealer | 3147 |
| threatfox | 2994 |
| ClickFix | 1797 |
| cve | 1764 |
| exploited-in-the-wild | 1764 |
| drop | 1416 |
| spamhaus | 1416 |

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
| ipv4: 92[.]249[.]61[.]190 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
