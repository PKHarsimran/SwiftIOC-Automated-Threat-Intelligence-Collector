# SwiftIOC IOC Summary

_Generated 2026-09-19T02:50:45Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-19T02:50:45Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 9722 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 930 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 930 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-19T02:30:26Z |

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
| ipsum_level5 | 6371 |
| blocklist_de_ssh | 5767 |
| greensnow_blocklist | 5718 |
| binarydefense_banlist | 4792 |
| nist_nvd_recent | 2800 |
| threatfox_export_json | 2733 |
| cisa_kev | 1716 |
| spamhaus_drop | 1713 |
| malwarebazaar_recent | 1443 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3365 |
| sha256 | 2818 |
| ipv4_cidr | 1710 |
| domain | 835 |
| url | 644 |
| ipv4 | 306 |
| sha1 | 265 |
| md5 | 57 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3430 |
| cve | 3365 |
| threatfox | 2146 |
| nvd | 1901 |
| exploited-in-the-wild | 1716 |
| drop | 1710 |
| spamhaus | 1710 |
| high | 683 |
| Mirai | 551 |
| malware_download | 440 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
