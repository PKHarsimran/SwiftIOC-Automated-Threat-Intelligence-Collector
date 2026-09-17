# SwiftIOC IOC Summary

_Generated 2026-09-17T22:36:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-17T22:36:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6782 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 894 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 894 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-17T22:36:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 4835 |
| blocklist_de_ssh | 4714 |
| binarydefense_banlist | 4355 |
| greensnow_blocklist | 4300 |
| nist_nvd_recent | 3000 |
| threatfox_export_json | 2770 |
| spamhaus_drop | 1714 |
| cisa_kev | 1713 |
| malwarebazaar_recent | 1546 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3906 |
| sha256 | 2112 |
| ipv4_cidr | 1713 |
| url | 856 |
| domain | 843 |
| ipv4 | 274 |
| sha1 | 252 |
| md5 | 44 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3906 |
| malware | 2910 |
| nvd | 2442 |
| threatfox | 2088 |
| exploited-in-the-wild | 1713 |
| drop | 1713 |
| spamhaus | 1713 |
| high | 1195 |
| malware_download | 624 |
| medium | 527 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
