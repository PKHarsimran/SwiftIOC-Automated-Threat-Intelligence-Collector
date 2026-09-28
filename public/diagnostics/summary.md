# SwiftIOC IOC Summary

_Generated 2026-09-28T19:08:42Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-28T19:08:42Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5962 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1328 |
| Score (min / avg / max) | 80 / 80.7 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1328 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-09-28T19:08:16Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `176[.]65[.]139[.]206` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
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
| blocklist_de_ssh | 11800 |
| threatfox_export_json | 6146 |
| greensnow_blocklist | 4869 |
| ipsum_level5 | 4467 |
| cisa_kev | 1728 |
| spamhaus_drop | 1693 |
| tor_exit_nodes | 1366 |
| malwarebazaar_recent | 1295 |
| nist_nvd_recent | 1160 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 2981 |
| cve | 2524 |
| ipv4_cidr | 1692 |
| domain | 1334 |
| url | 1045 |
| sha1 | 234 |
| ipv4 | 164 |
| md5 | 26 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3701 |
| threatfox | 3094 |
| cve | 2524 |
| exploited-in-the-wild | 1728 |
| drop | 1692 |
| spamhaus | 1692 |
| Mirai | 1402 |
| nvd | 1082 |
| etherhiding | 956 |
| malware_download | 793 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 176[.]65[.]139[.]206 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
