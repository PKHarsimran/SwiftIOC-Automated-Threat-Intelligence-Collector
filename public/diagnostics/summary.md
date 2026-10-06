# SwiftIOC IOC Summary

_Generated 2026-10-06T14:41:22Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-06T14:41:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6085 |
| Sources reporting | 17 |
| Indicator types | 6 |
| Multi-group overlaps | 335 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 335 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-06T14:32:34Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]60` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `45[.]17[.]39[.]120` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `107[.]172[.]132[.]240` | score 88, 2 reporting groups |
| ipv4: `139[.]162[.]5[.]254` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 14545 |
| threatfox_export_json | 5348 |
| greensnow_blocklist | 4924 |
| ipsum_level5 | 4122 |
| blocklist_de_ssh | 4060 |
| nist_nvd_recent | 2119 |
| binarydefense_banlist | 1976 |
| cisa_kev | 1734 |
| spamhaus_drop | 1641 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 4820 |
| cve | 2111 |
| ipv4_cidr | 1640 |
| domain | 1045 |
| sha256 | 341 |
| ipv4 | 43 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 5073 |
| malware_download | 4795 |
| zip | 4694 |
| github | 4687 |
| LuaJIT-loader | 4672 |
| SmartLoader | 4672 |
| cve | 2111 |
| exploited-in-the-wild | 1734 |
| drop | 1640 |
| spamhaus | 1640 |

## Multi-group reporting overlaps

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
