# SwiftIOC IOC Summary

_Generated 2026-10-05T21:09:57Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-05T21:09:57Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4892 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 1724 |
| Score (min / avg / max) | 80 / 81.0 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 1724 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-05T21:05:05Z |

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
| ipv4: `103[.]176[.]64[.]36` | score 91, 4 sources |
| sha256: `01b5a60b54ff4a0f670e39a6d567f02bc69338ccfae2d679a17ed09247e284e6` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 4917 |
| threatfox_export_json | 4372 |
| ipsum_level5 | 3531 |
| blocklist_de_ssh | 2809 |
| cisa_kev | 1734 |
| binarydefense_banlist | 1677 |
| spamhaus_drop | 1641 |
| nist_nvd_recent | 1465 |
| tor_exit_nodes | 1356 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4390 |
| cve | 2161 |
| ipv4_cidr | 1498 |
| url | 989 |
| domain | 595 |
| ipv4 | 175 |
| md5 | 108 |
| sha1 | 84 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4586 |
| malware | 3145 |
| elf | 2455 |
| Mirai | 2431 |
| cve | 2189 |
| exploited-in-the-wild | 1734 |
| drop | 1498 |
| spamhaus | 1498 |
| malware_download | 818 |
| nvd | 736 |

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
