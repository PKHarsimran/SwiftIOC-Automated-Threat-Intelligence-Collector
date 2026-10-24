# SwiftIOC IOC Summary

_Generated 2026-10-24T22:12:47Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-24T22:12:47Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6822 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 405 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 405 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-24T22:07:42Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| urlhaus_recent_urls | 33922 |
| ci_army_list | 15000 |
| ipsum_level5 | 5289 |
| blocklist_de_ssh | 4630 |
| greensnow_blocklist | 4533 |
| threatfox_export_json | 2873 |
| nist_nvd_recent | 2400 |
| cisa_kev | 1756 |
| spamhaus_drop | 1688 |
| tor_exit_nodes | 1212 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5684 |
| cve | 1756 |
| ipv4_cidr | 1687 |
| domain | 325 |
| sha256 | 302 |
| ipv4 | 93 |
| md5 | 77 |
| sha1 | 76 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 5753 |
| malware_download | 5605 |
| zip | 5431 |
| github | 5429 |
| SmartLoader | 4280 |
| cve | 1756 |
| exploited-in-the-wild | 1756 |
| drop | 1687 |
| spamhaus | 1687 |
| SalatStealer | 1163 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
