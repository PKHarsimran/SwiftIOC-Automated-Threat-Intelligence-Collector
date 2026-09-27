# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-27T03:18:06Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-27T03:18:06Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9339 |
| Sources reporting | 16 |
| Indicator types | 7 |
| Multi-source overlaps | 1225 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1225 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-27T03:04:15Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `176[.]65[.]139[.]206` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| binarydefense_banlist | 6344 |
| greensnow_blocklist | 5760 |
| ipsum_level5 | 5109 |
| blocklist_de_ssh | 5015 |
| nist_nvd_recent | 2311 |
| cisa_kev | 1726 |
| spamhaus_drop | 1711 |
| tor_exit_nodes | 1376 |
| malwarebazaar_recent | 1200 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4805 |
| sha256 | 2647 |
| ipv4_cidr | 1710 |
| url | 567 |
| sha1 | 228 |
| ipv4 | 23 |
| md5 | 20 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4805 |
| nvd | 3363 |
| malware | 3284 |
| exploited-in-the-wild | 1726 |
| drop | 1710 |
| spamhaus | 1710 |
| high | 1317 |
| Mirai | 1289 |
| threatfox | 1107 |
| medium | 842 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
