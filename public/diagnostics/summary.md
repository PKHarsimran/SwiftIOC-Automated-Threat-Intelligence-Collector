# SwiftIOC IOC Summary

_Generated 2026-10-07T18:20:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-07T18:20:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6581 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 341 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 341 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-07T18:19:45Z |

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
| urlhaus_recent_urls | 14319 |
| blocklist_de_ssh | 4904 |
| ipsum_level5 | 4864 |
| greensnow_blocklist | 4784 |
| nist_nvd_recent | 3800 |
| threatfox_export_json | 3392 |
| binarydefense_banlist | 2241 |
| cisa_kev | 1734 |
| spamhaus_drop | 1671 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3127 |
| cve | 2914 |
| ipv4_cidr | 1670 |
| domain | 1226 |
| sha256 | 602 |
| ipv4 | 157 |
| md5 | 152 |
| sha1 | 152 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3546 |
| malware_download | 3013 |
| cve | 2914 |
| github | 2564 |
| zip | 2564 |
| LuaJIT-loader | 2552 |
| SmartLoader | 2552 |
| threatfox | 1957 |
| exploited-in-the-wild | 1734 |
| drop | 1670 |

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
