# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-03T21:27:27Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-03T21:27:27Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5597 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 428 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 428 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-03T21:27:02Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 90, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 90, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 5699 |
| blocklist_de_ssh | 4880 |
| threatfox_export_json | 4642 |
| ipsum_level5 | 4456 |
| greensnow_blocklist | 2815 |
| nist_nvd_recent | 2399 |
| cisa_kev | 1767 |
| spamhaus_drop | 1761 |
| tor_exit_nodes | 1243 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5063 |
| cve | 1986 |
| ipv4_cidr | 1760 |
| sha256 | 550 |
| domain | 358 |
| ipv4 | 125 |
| md5 | 79 |
| sha1 | 79 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4941 |
| malware_download | 4669 |
| github | 4522 |
| zapret | 4243 |
| SalatStealer | 4230 |
| cve | 1986 |
| exploited-in-the-wild | 1767 |
| drop | 1760 |
| spamhaus | 1760 |
| threatfox | 1428 |

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
