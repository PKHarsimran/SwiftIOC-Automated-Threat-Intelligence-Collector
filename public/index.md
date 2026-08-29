# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-29T22:13:40Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-29T22:13:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4828 |
| Sources reporting | 16 |
| Indicator types | 9 |
| Multi-source overlaps | 248 |
| Score (min / avg / max) | 77 / 79.8 / 96 |
| High-score indicators (≥80) | 7019 |
| Corroborated (2+ sources) | 248 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-29T22:08:30Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `106[.]13[.]46[.]38` | score 96, 4 sources |
| ipv4: `145[.]239[.]85[.]111` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `186[.]209[.]77[.]237` | score 96, 4 sources |
| ipv4: `206[.]42[.]5[.]12` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `87[.]251[.]66[.]91` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 13139 |
| greensnow_blocklist | 4363 |
| ipsum_level5 | 2800 |
| spamhaus_drop | 1706 |
| cisa_kev | 1685 |
| threatfox_export_json | 1652 |
| tor_exit_nodes | 1430 |
| binarydefense_banlist | 1062 |
| malwarebazaar_recent | 811 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3387 |
| cve | 2518 |
| ipv4_cidr | 1705 |
| domain | 1036 |
| url | 557 |
| md5 | 258 |
| sha1 | 252 |
| ipv4 | 190 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3573 |
| cve | 2518 |
| threatfox | 2116 |
| drop | 1705 |
| spamhaus | 1705 |
| exploited-in-the-wild | 1685 |
| Mirai | 1180 |
| nvd | 1048 |
| Sepolia | 680 |
| etherhiding | 680 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 106[.]13[.]46[.]38 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 145[.]239[.]85[.]111 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 186[.]209[.]77[.]237 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 87[.]251[.]66[.]91 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
