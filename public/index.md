# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-30T03:13:55Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-30T03:13:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5431 |
| Sources reporting | 16 |
| Indicator types | 9 |
| Multi-source overlaps | 249 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7210 |
| Corroborated (2+ sources) | 249 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-30T03:02:06Z |

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
| ipv4: `197[.]140[.]9[.]148` | score 96, 4 sources |
| ipv4: `206[.]42[.]5[.]12` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 13096 |
| greensnow_blocklist | 5266 |
| ipsum_level5 | 2790 |
| spamhaus_drop | 1706 |
| cisa_kev | 1685 |
| threatfox_export_json | 1548 |
| tor_exit_nodes | 1430 |
| binarydefense_banlist | 1297 |
| malwarebazaar_recent | 836 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3440 |
| cve | 2666 |
| ipv4_cidr | 1705 |
| domain | 903 |
| url | 529 |
| md5 | 247 |
| sha1 | 240 |
| ipv4 | 173 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3616 |
| cve | 2666 |
| threatfox | 1925 |
| drop | 1705 |
| spamhaus | 1705 |
| exploited-in-the-wild | 1685 |
| Mirai | 1217 |
| nvd | 1197 |
| high | 617 |
| Sepolia | 591 |

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
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
