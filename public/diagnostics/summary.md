# SwiftIOC IOC Summary

_Generated 2026-11-03T05:02:17Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-03T05:02:17Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7180 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 427 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 427 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-03T05:01:10Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| threatfox_export_json | 4907 |
| blocklist_de_ssh | 4850 |
| ipsum_level5 | 4456 |
| urlhaus_recent_urls | 3860 |
| greensnow_blocklist | 3783 |
| cisa_kev | 1766 |
| spamhaus_drop | 1757 |
| nist_nvd_recent | 1697 |
| tor_exit_nodes | 1240 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3812 |
| cve | 2276 |
| domain | 1064 |
| sha256 | 963 |
| ipv4 | 876 |
| ipv4_cidr | 875 |
| md5 | 67 |
| sha1 | 67 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4156 |
| malware_download | 3649 |
| github | 3562 |
| SalatStealer | 3427 |
| zapret | 3150 |
| threatfox | 2881 |
| cve | 2276 |
| exploited-in-the-wild | 1766 |
| nvd | 909 |
| drop | 875 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 156[.]225[.]17[.]60 | binarydefense_banlist, ci_army_list, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
