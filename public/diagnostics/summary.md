# SwiftIOC IOC Summary

_Generated 2026-08-29T10:40:56Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-29T10:40:56Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4263 |
| Sources reporting | 16 |
| Indicator types | 9 |
| Multi-source overlaps | 250 |
| Score (min / avg / max) | 77 / 79.9 / 96 |
| High-score indicators (≥80) | 7324 |
| Corroborated (2+ sources) | 250 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-29T10:31:29Z |

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
| blocklist_de_ssh | 13341 |
| greensnow_blocklist | 3234 |
| ipsum_level5 | 2800 |
| threatfox_export_json | 1805 |
| spamhaus_drop | 1706 |
| cisa_kev | 1685 |
| tor_exit_nodes | 1416 |
| binarydefense_banlist | 1062 |
| malwarebazaar_recent | 804 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3289 |
| cve | 2506 |
| ipv4_cidr | 1705 |
| domain | 1047 |
| url | 601 |
| md5 | 281 |
| sha1 | 274 |
| ipv4 | 200 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3451 |
| cve | 2506 |
| threatfox | 2253 |
| drop | 1705 |
| spamhaus | 1705 |
| exploited-in-the-wild | 1685 |
| Mirai | 1147 |
| nvd | 1035 |
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
