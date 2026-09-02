# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-02T02:32:52Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-02T02:32:52Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4823 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 245 |
| Score (min / avg / max) | 78 / 79.8 / 96 |
| High-score indicators (≥80) | 6537 |
| Corroborated (2+ sources) | 245 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-02T02:21:22Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `197[.]140[.]9[.]148` | score 96, 4 sources |
| ipv4: `206[.]42[.]5[.]12` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `87[.]251[.]66[.]91` | score 96, 4 sources |
| ipv4: `152[.]228[.]135[.]87` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 13076 |
| greensnow_blocklist | 5298 |
| ipsum_level5 | 2738 |
| spamhaus_drop | 1710 |
| cisa_kev | 1687 |
| tor_exit_nodes | 1420 |
| threatfox_export_json | 1195 |
| malwarebazaar_recent | 681 |
| urlhaus_recent_urls | 560 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3248 |
| cve | 3175 |
| ipv4_cidr | 1710 |
| url | 780 |
| ipv4 | 296 |
| md5 | 240 |
| sha1 | 233 |
| domain | 221 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3642 |
| cve | 3175 |
| drop | 1710 |
| spamhaus | 1710 |
| nvd | 1706 |
| exploited-in-the-wild | 1687 |
| threatfox | 1374 |
| Mirai | 954 |
| high | 815 |
| malware_download | 656 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 197[.]140[.]9[.]148 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 206[.]42[.]5[.]12 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 87[.]251[.]66[.]91 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 152[.]228[.]135[.]87 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
