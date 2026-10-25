# SwiftIOC IOC Summary

_Generated 2026-10-25T15:27:09Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-25T15:27:09Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7007 |
| Sources reporting | 17 |
| Indicator types | 6 |
| Multi-group overlaps | 406 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 406 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-25T15:26:42Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `31[.]59[.]220[.]26` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| urlhaus_recent_urls | 44377 |
| ci_army_list | 15000 |
| ipsum_level5 | 5986 |
| threatfox_export_json | 4711 |
| blocklist_de_ssh | 4614 |
| greensnow_blocklist | 4489 |
| nist_nvd_recent | 3000 |
| cisa_kev | 1756 |
| spamhaus_drop | 1688 |
| tor_exit_nodes | 1213 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 6223 |
| cve | 1756 |
| ipv4_cidr | 1687 |
| sha256 | 154 |
| domain | 128 |
| ipv4 | 52 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 6272 |
| malware_download | 6189 |
| github | 6040 |
| zapret | 6040 |
| cve | 1756 |
| exploited-in-the-wild | 1756 |
| drop | 1687 |
| spamhaus | 1687 |
| nvd | 375 |
| threatfox | 288 |

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
