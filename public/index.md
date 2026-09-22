# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-22T11:57:09Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-22T11:57:09Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7230 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1084 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1084 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-22T11:50:06Z |

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
| blocklist_de_ssh | 5523 |
| binarydefense_banlist | 5363 |
| greensnow_blocklist | 4957 |
| ipsum_level5 | 3875 |
| threatfox_export_json | 2254 |
| cisa_kev | 1717 |
| spamhaus_drop | 1712 |
| malwarebazaar_recent | 1420 |
| nist_nvd_recent | 1414 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3424 |
| cve | 2814 |
| ipv4_cidr | 1715 |
| url | 1147 |
| domain | 388 |
| sha1 | 249 |
| ipv4 | 222 |
| md5 | 41 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4415 |
| cve | 2814 |
| threatfox | 1850 |
| exploited-in-the-wild | 1717 |
| drop | 1715 |
| spamhaus | 1715 |
| nvd | 1355 |
| malware_download | 946 |
| Mirai | 835 |
| high | 579 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
