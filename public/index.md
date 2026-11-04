# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-04T21:41:26Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-04T21:41:26Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5434 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 427 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 427 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-04T21:41:04Z |

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
| ipv4: `45[.]90[.]163[.]37` | score 89, 3 reporting groups |
| ipv4_cidr: `178.20.210.0/24` | score 88, 2 reporting groups |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 4594 |
| blocklist_de_ssh | 4534 |
| ipsum_level5 | 4410 |
| threatfox_export_json | 3180 |
| greensnow_blocklist | 2957 |
| nist_nvd_recent | 2200 |
| cisa_kev | 1768 |
| spamhaus_drop | 1763 |
| tor_exit_nodes | 1239 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3203 |
| cve | 2572 |
| ipv4_cidr | 1763 |
| sha256 | 1379 |
| domain | 526 |
| ipv4 | 235 |
| md5 | 161 |
| sha1 | 161 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3457 |
| malware_download | 2641 |
| cve | 2572 |
| threatfox | 2444 |
| github | 2158 |
| zapret | 2005 |
| SalatStealer | 1905 |
| exploited-in-the-wild | 1768 |
| drop | 1763 |
| spamhaus | 1763 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 156[.]225[.]17[.]60 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| ipv4: 180[.]93[.]193[.]100 | ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
