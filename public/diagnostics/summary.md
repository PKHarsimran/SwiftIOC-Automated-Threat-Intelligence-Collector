# SwiftIOC IOC Summary

_Generated 2026-09-01T09:06:01Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-01T09:06:01Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4111 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 248 |
| Score (min / avg / max) | 78 / 79.8 / 96 |
| High-score indicators (≥80) | 6538 |
| Corroborated (2+ sources) | 248 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-09-01T08:49:10Z |

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
| blocklist_de_ssh | 12456 |
| greensnow_blocklist | 5156 |
| binarydefense_banlist | 1852 |
| spamhaus_drop | 1708 |
| cisa_kev | 1687 |
| ipsum_level5 | 1591 |
| tor_exit_nodes | 1419 |
| threatfox_export_json | 1006 |
| malwarebazaar_recent | 710 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3537 |
| cve | 3157 |
| ipv4_cidr | 1707 |
| url | 580 |
| ipv4 | 247 |
| domain | 236 |
| md5 | 223 |
| sha1 | 216 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3746 |
| cve | 3157 |
| drop | 1707 |
| spamhaus | 1707 |
| nvd | 1688 |
| exploited-in-the-wild | 1687 |
| threatfox | 1292 |
| Mirai | 1090 |
| high | 797 |
| medium | 493 |

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
