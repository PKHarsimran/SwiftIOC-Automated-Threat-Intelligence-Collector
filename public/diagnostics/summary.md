# SwiftIOC IOC Summary

_Generated 2026-10-31T16:42:55Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-31T16:42:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4090 |
| Sources reporting | 16 |
| Indicator types | 6 |
| Multi-group overlaps | 425 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 425 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-31T16:42:32Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 91, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4934 |
| ipsum_level5 | 4867 |
| threatfox_export_json | 4713 |
| urlhaus_recent_urls | 3476 |
| nist_nvd_recent | 2600 |
| cisa_kev | 1766 |
| spamhaus_drop | 1756 |
| tor_exit_nodes | 1221 |
| malwarebazaar_recent | 960 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 3587 |
| cve | 1898 |
| ipv4_cidr | 1580 |
| sha256 | 1344 |
| domain | 1299 |
| ipv4 | 292 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4023 |
| malware_download | 3119 |
| threatfox | 2798 |
| github | 2506 |
| cve | 1898 |
| SalatStealer | 1881 |
| exploited-in-the-wild | 1766 |
| drop | 1580 |
| spamhaus | 1580 |
| ClickFix | 1468 |

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
