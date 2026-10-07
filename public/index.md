# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-10-07T10:51:38Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-07T10:51:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6321 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 333 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 333 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-07T10:50:57Z |

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
| ipv4: `139[.]162[.]5[.]254` | score 88, 2 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 14472 |
| blocklist_de_ssh | 4935 |
| ipsum_level5 | 4864 |
| threatfox_export_json | 3584 |
| greensnow_blocklist | 3544 |
| nist_nvd_recent | 2600 |
| binarydefense_banlist | 2241 |
| cisa_kev | 1734 |
| spamhaus_drop | 1660 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3647 |
| cve | 2667 |
| ipv4_cidr | 1659 |
| domain | 1169 |
| sha256 | 554 |
| ipv4 | 130 |
| md5 | 87 |
| sha1 | 87 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4063 |
| malware_download | 3587 |
| zip | 3181 |
| github | 3174 |
| LuaJIT-loader | 3159 |
| SmartLoader | 3159 |
| cve | 2667 |
| exploited-in-the-wild | 1734 |
| drop | 1659 |
| spamhaus | 1659 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
