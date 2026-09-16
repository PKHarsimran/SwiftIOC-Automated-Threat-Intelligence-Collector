# SwiftIOC IOC Summary

_Generated 2026-09-16T09:00:37Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-16T09:00:37Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6662 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-source overlaps | 854 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 854 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-16T08:45:42Z |

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
| greensnow_blocklist | 5400 |
| blocklist_de_ssh | 4717 |
| binarydefense_banlist | 4148 |
| ipsum_level5 | 4117 |
| threatfox_export_json | 3667 |
| spamhaus_drop | 1725 |
| cisa_kev | 1710 |
| malwarebazaar_recent | 1356 |
| tor_exit_nodes | 1345 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3527 |
| sha256 | 2444 |
| ipv4_cidr | 1613 |
| domain | 1483 |
| url | 524 |
| sha1 | 220 |
| ipv4 | 177 |
| md5 | 12 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3527 |
| threatfox | 3364 |
| malware | 2075 |
| nvd | 2063 |
| exploited-in-the-wild | 1710 |
| drop | 1613 |
| spamhaus | 1613 |
| Sepolia | 1010 |
| etherhiding | 1006 |
| rat | 956 |

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
