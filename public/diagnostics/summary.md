# SwiftIOC IOC Summary

_Generated 2026-10-06T04:31:40Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-06T04:31:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6405 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1746 |
| Score (min / avg / max) | 80 / 81.0 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1746 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-06T04:30:28Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `165[.]154[.]162[.]74` | score 96, 4 sources |
| ipv4: `165[.]154[.]227[.]8` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `45[.]198[.]224[.]184` | score 96, 4 sources |
| ipv4: `45[.]78[.]201[.]248` | score 96, 4 sources |
| ipv4: `103[.]176[.]64[.]36` | score 89, 4 sources |
| sha256: `01b5a60b54ff4a0f670e39a6d567f02bc69338ccfae2d679a17ed09247e284e6` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5556 |
| threatfox_export_json | 4547 |
| ipsum_level5 | 4122 |
| blocklist_de_ssh | 3408 |
| binarydefense_banlist | 1976 |
| cisa_kev | 1734 |
| spamhaus_drop | 1641 |
| nist_nvd_recent | 1622 |
| tor_exit_nodes | 1363 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4308 |
| cve | 2245 |
| ipv4_cidr | 1326 |
| url | 990 |
| domain | 763 |
| ipv4 | 176 |
| md5 | 108 |
| sha1 | 84 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4739 |
| malware | 3102 |
| Mirai | 2409 |
| elf | 2389 |
| cve | 2273 |
| exploited-in-the-wild | 1734 |
| drop | 1326 |
| spamhaus | 1326 |
| nvd | 820 |
| malware_download | 813 |

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
