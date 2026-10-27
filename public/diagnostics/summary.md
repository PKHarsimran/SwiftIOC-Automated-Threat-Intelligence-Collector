# SwiftIOC IOC Summary

_Generated 2026-10-27T23:26:13Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-27T23:26:13Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6041 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 420 |
| Score (min / avg / max) | 80 / 80.3 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 420 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-10-27T23:25:41Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `156[.]225[.]17[.]60` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| urlhaus_recent_urls | 21933 |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5297 |
| greensnow_blocklist | 4846 |
| ipsum_level5 | 4197 |
| threatfox_export_json | 3242 |
| nist_nvd_recent | 3000 |
| malwarebazaar_recent | 2039 |
| cisa_kev | 1760 |
| spamhaus_drop | 1760 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| url | 4322 |
| cve | 1760 |
| ipv4_cidr | 1759 |
| sha256 | 1521 |
| domain | 181 |
| md5 | 169 |
| sha1 | 168 |
| ipv4 | 120 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 5031 |
| malware_download | 3891 |
| github | 3153 |
| zapret | 2240 |
| threatfox | 1888 |
| cve | 1760 |
| exploited-in-the-wild | 1760 |
| drop | 1759 |
| spamhaus | 1759 |
| SalatStealer | 1338 |

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
