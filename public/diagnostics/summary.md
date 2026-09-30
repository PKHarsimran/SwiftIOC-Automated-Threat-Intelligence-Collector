# SwiftIOC IOC Summary

_Generated 2026-09-30T10:14:44Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-30T10:14:44Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5439 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1339 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1339 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-30T10:05:15Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 6 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
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
| blocklist_de_ssh | 5388 |
| ipsum_level5 | 4277 |
| greensnow_blocklist | 3689 |
| nist_nvd_recent | 2588 |
| threatfox_export_json | 1914 |
| cisa_kev | 1729 |
| spamhaus_drop | 1694 |
| tor_exit_nodes | 1408 |
| malwarebazaar_recent | 1318 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3328 |
| cve | 2878 |
| ipv4_cidr | 1577 |
| url | 847 |
| domain | 720 |
| ipv4 | 401 |
| sha1 | 199 |
| md5 | 50 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3693 |
| cve | 2878 |
| threatfox | 2874 |
| exploited-in-the-wild | 1729 |
| drop | 1577 |
| spamhaus | 1577 |
| Mirai | 1446 |
| nvd | 1437 |
| malware_download | 634 |
| high | 439 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
