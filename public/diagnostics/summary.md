# SwiftIOC IOC Summary

_Generated 2026-09-22T00:38:19Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-22T00:38:19Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9497 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1064 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1064 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-22T00:34:56Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5922 |
| ipsum_level5 | 5793 |
| blocklist_de_ssh | 5607 |
| binarydefense_banlist | 5363 |
| threatfox_export_json | 2112 |
| cisa_kev | 1717 |
| spamhaus_drop | 1716 |
| malwarebazaar_recent | 1424 |
| tor_exit_nodes | 1378 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3322 |
| sha256 | 3205 |
| ipv4_cidr | 1715 |
| url | 866 |
| domain | 370 |
| sha1 | 262 |
| ipv4 | 206 |
| md5 | 54 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4022 |
| cve | 3322 |
| nvd | 1863 |
| exploited-in-the-wild | 1717 |
| threatfox | 1715 |
| drop | 1715 |
| spamhaus | 1715 |
| high | 835 |
| malware_download | 707 |
| Mirai | 686 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
