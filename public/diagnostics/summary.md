# SwiftIOC IOC Summary

_Generated 2026-10-28T10:16:55Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-28T10:16:55Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 8251 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 424 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 424 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-28T10:10:58Z |

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
| ipv4: `92[.]249[.]61[.]190` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| urlhaus_recent_urls | 10742 |
| ipsum_level5 | 6086 |
| greensnow_blocklist | 5473 |
| blocklist_de_ssh | 5193 |
| threatfox_export_json | 3220 |
| nist_nvd_recent | 3200 |
| cisa_kev | 1760 |
| spamhaus_drop | 1760 |
| malwarebazaar_recent | 1621 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 5258 |
| cve | 2029 |
| ipv4_cidr | 1759 |
| sha256 | 611 |
| domain | 100 |
| sha1 | 90 |
| md5 | 89 |
| ipv4 | 64 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 5318 |
| malware_download | 4966 |
| github | 4699 |
| zapret | 3778 |
| SalatStealer | 2239 |
| cve | 2029 |
| exploited-in-the-wild | 1760 |
| drop | 1759 |
| spamhaus | 1759 |
| threatfox | 1043 |

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
| ipv4: 31[.]59[.]220[.]26 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
