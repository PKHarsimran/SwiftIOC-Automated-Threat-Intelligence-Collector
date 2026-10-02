# SwiftIOC IOC Summary

_Generated 2026-10-02T17:19:34Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-02T17:19:34Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4253 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1468 |
| Score (min / avg / max) | 80 / 80.8 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1468 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-02T17:10:23Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `45[.]198[.]224[.]184` | score 96, 4 sources |
| ipv4: `45[.]78[.]201[.]248` | score 96, 4 sources |
| ipv4: `176[.]65[.]148[.]49` | score 96, 3 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 4909 |
| ipsum_level5 | 4372 |
| nist_nvd_recent | 2600 |
| threatfox_export_json | 2414 |
| cisa_kev | 1733 |
| blocklist_de_ssh | 1699 |
| spamhaus_drop | 1693 |
| tor_exit_nodes | 1384 |
| malwarebazaar_recent | 1129 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3056 |
| cve | 2706 |
| ipv4_cidr | 1692 |
| url | 1049 |
| domain | 1025 |
| ipv4 | 237 |
| sha1 | 170 |
| md5 | 65 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3396 |
| threatfox | 3340 |
| cve | 2706 |
| exploited-in-the-wild | 1733 |
| drop | 1692 |
| spamhaus | 1692 |
| nvd | 1279 |
| Mirai | 997 |
| ClickFix | 884 |
| malware_download | 723 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
