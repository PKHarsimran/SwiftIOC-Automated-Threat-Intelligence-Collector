# SwiftIOC IOC Summary

_Generated 2026-09-16T16:00:48Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-16T16:00:48Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6180 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 868 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 868 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-16T15:59:22Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4625 |
| greensnow_blocklist | 4548 |
| binarydefense_banlist | 4148 |
| ipsum_level5 | 4117 |
| nist_nvd_recent | 3820 |
| threatfox_export_json | 3315 |
| spamhaus_drop | 1715 |
| cisa_kev | 1711 |
| malwarebazaar_recent | 1659 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3692 |
| sha256 | 2766 |
| domain | 1328 |
| ipv4_cidr | 908 |
| url | 863 |
| sha1 | 229 |
| ipv4 | 193 |
| md5 | 21 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3692 |
| threatfox | 3278 |
| malware | 2714 |
| nvd | 2228 |
| exploited-in-the-wild | 1711 |
| high | 1051 |
| etherhiding | 1026 |
| Sepolia | 1010 |
| rat | 956 |
| asyncrat | 952 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
