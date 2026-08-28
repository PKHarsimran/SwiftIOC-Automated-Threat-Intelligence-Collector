# SwiftIOC IOC Summary

_Generated 2026-08-28T16:28:51Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-28T16:28:51Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4386 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 249 |
| Score (min / avg / max) | 79 / 80.0 / 96 |
| High-score indicators (≥80) | 7928 |
| Corroborated (2+ sources) | 249 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-28T16:28:30Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `145[.]239[.]85[.]111` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 4 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 3 sources |
| ipv4: `106[.]13[.]46[.]38` | score 96, 3 sources |
| ipv4: `152[.]228[.]135[.]87` | score 96, 3 sources |
| ipv4: `206[.]42[.]5[.]12` | score 96, 3 sources |
| ipv4: `80[.]15[.]193[.]156` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 13267 |
| greensnow_blocklist | 4606 |
| threatfox_export_json | 2428 |
| ipsum_level5 | 2236 |
| spamhaus_drop | 1706 |
| cisa_kev | 1685 |
| tor_exit_nodes | 1400 |
| malwarebazaar_recent | 845 |
| binarydefense_banlist | 753 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3126 |
| cve | 2496 |
| ipv4_cidr | 1706 |
| domain | 1132 |
| url | 571 |
| ipv4 | 317 |
| md5 | 281 |
| sha1 | 274 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3179 |
| threatfox | 2528 |
| cve | 2496 |
| drop | 1706 |
| spamhaus | 1706 |
| exploited-in-the-wild | 1685 |
| Mirai | 1047 |
| nvd | 1025 |
| etherhiding | 731 |
| Sepolia | 680 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 145[.]239[.]85[.]111 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, threatfox_export_json |
| ipv4: 106[.]13[.]46[.]38 | blocklist_de_ssh, greensnow_blocklist, threatfox_export_json |
| ipv4: 152[.]228[.]135[.]87 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |
| ipv4: 80[.]15[.]193[.]156 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
