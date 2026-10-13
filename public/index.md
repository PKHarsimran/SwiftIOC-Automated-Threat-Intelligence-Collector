# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-13T20:57:29Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-13T20:57:29Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7462 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 374 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 374 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-13T20:57:06Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `165[.]245[.]171[.]220` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `36[.]50[.]134[.]86` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 5079 |
| greensnow_blocklist | 4912 |
| blocklist_de_ssh | 4212 |
| binarydefense_banlist | 3918 |
| threatfox_export_json | 3003 |
| nist_nvd_recent | 2600 |
| cisa_kev | 1741 |
| spamhaus_drop | 1681 |
| tor_exit_nodes | 1214 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3522 |
| url | 2442 |
| sha256 | 1845 |
| ipv4_cidr | 996 |
| domain | 593 |
| ipv4 | 300 |
| md5 | 151 |
| sha1 | 151 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3522 |
| threatfox | 3217 |
| malware | 2845 |
| nvd | 2124 |
| exploited-in-the-wild | 1741 |
| malware_download | 1101 |
| drop | 996 |
| spamhaus | 996 |
| medium | 920 |
| Mirai | 808 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]245[.]171[.]220 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
