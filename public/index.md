# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-05T08:58:30Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-05T08:58:30Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3594 |
| Sources reporting | 16 |
| Indicator types | 8 |
| Multi-source overlaps | 1678 |
| Score (min / avg / max) | 80 / 80.9 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1678 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-05T08:47:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `45[.]198[.]224[.]184` | score 96, 4 sources |
| ipv4: `45[.]78[.]201[.]248` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 94, 4 sources |
| sha256: `01b5a60b54ff4a0f670e39a6d567f02bc69338ccfae2d679a17ed09247e284e6` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5325 |
| threatfox_export_json | 4196 |
| ipsum_level5 | 3531 |
| cisa_kev | 1734 |
| spamhaus_drop | 1692 |
| binarydefense_banlist | 1677 |
| tor_exit_nodes | 1380 |
| malwarebazaar_recent | 1059 |
| urlhaus_recent_urls | 913 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4121 |
| cve | 2255 |
| ipv4_cidr | 1691 |
| url | 1089 |
| domain | 518 |
| ipv4 | 182 |
| md5 | 74 |
| sha1 | 70 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4341 |
| malware | 3058 |
| elf | 2389 |
| Mirai | 2296 |
| cve | 2283 |
| exploited-in-the-wild | 1734 |
| drop | 1691 |
| spamhaus | 1691 |
| malware_download | 916 |
| nvd | 830 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
