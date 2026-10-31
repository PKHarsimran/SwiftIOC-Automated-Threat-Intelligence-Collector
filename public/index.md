# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-31T10:07:52Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-31T10:07:52Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6523 |
| Sources reporting | 17 |
| Indicator types | 6 |
| Multi-group overlaps | 425 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 425 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-31T10:07:29Z |

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
| ipv4: `156[.]225[.]17[.]60` | score 94, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 5049 |
| blocklist_de_ssh | 4870 |
| ipsum_level5 | 4867 |
| threatfox_export_json | 4820 |
| greensnow_blocklist | 3844 |
| nist_nvd_recent | 2800 |
| cisa_kev | 1766 |
| spamhaus_drop | 1757 |
| tor_exit_nodes | 1225 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3286 |
| domain | 2280 |
| cve | 1939 |
| sha256 | 1182 |
| ipv4_cidr | 1047 |
| ipv4 | 266 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3690 |
| malware | 3503 |
| malware_download | 2793 |
| github | 2382 |
| ClickFix | 2375 |
| SalatStealer | 2018 |
| cve | 1939 |
| exploited-in-the-wild | 1766 |
| exe | 1231 |
| drop | 1047 |

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
