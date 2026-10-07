# SwiftIOC IOC Summary

_Generated 2026-10-07T03:56:43Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-07T03:56:43Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7489 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 335 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 335 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-07T03:47:32Z |

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
| urlhaus_recent_urls | 14647 |
| greensnow_blocklist | 5737 |
| ipsum_level5 | 4864 |
| blocklist_de_ssh | 4668 |
| threatfox_export_json | 3891 |
| nist_nvd_recent | 2400 |
| binarydefense_banlist | 2241 |
| cisa_kev | 1734 |
| spamhaus_drop | 1641 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3891 |
| cve | 2667 |
| ipv4_cidr | 1640 |
| domain | 1128 |
| sha256 | 425 |
| md5 | 87 |
| sha1 | 87 |
| ipv4 | 75 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4215 |
| malware_download | 3854 |
| zip | 3507 |
| github | 3500 |
| LuaJIT-loader | 3485 |
| SmartLoader | 3485 |
| cve | 2667 |
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
