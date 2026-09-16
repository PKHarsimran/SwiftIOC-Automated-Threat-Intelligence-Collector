# SwiftIOC IOC Summary

_Generated 2026-09-16T19:28:44Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-16T19:28:44Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6200 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 869 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 869 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-16T19:28:19Z |

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
| blocklist_de_ssh | 4714 |
| greensnow_blocklist | 4509 |
| binarydefense_banlist | 4148 |
| ipsum_level5 | 4117 |
| threatfox_export_json | 3295 |
| nist_nvd_recent | 2600 |
| spamhaus_drop | 1715 |
| cisa_kev | 1713 |
| malwarebazaar_recent | 1614 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3680 |
| sha256 | 2593 |
| domain | 1392 |
| ipv4_cidr | 1083 |
| url | 808 |
| sha1 | 229 |
| ipv4 | 194 |
| md5 | 21 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3680 |
| threatfox | 3084 |
| malware | 2746 |
| nvd | 2214 |
| exploited-in-the-wild | 1713 |
| drop | 1083 |
| spamhaus | 1083 |
| high | 1056 |
| etherhiding | 1026 |
| Sepolia | 1010 |

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
