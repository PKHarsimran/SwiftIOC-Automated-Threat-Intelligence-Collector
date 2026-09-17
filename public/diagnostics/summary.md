# SwiftIOC IOC Summary

_Generated 2026-09-17T09:07:44Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-17T09:07:44Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7156 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 871 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 871 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-17T09:03:17Z |

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
| greensnow_blocklist | 5214 |
| ipsum_level5 | 4835 |
| blocklist_de_ssh | 4759 |
| binarydefense_banlist | 4355 |
| nist_nvd_recent | 2400 |
| threatfox_export_json | 2323 |
| spamhaus_drop | 1715 |
| cisa_kev | 1713 |
| malwarebazaar_recent | 1530 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4378 |
| sha256 | 2096 |
| ipv4_cidr | 1714 |
| url | 773 |
| domain | 534 |
| ipv4 | 255 |
| sha1 | 229 |
| md5 | 21 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4378 |
| nvd | 2913 |
| malware | 2852 |
| drop | 1714 |
| spamhaus | 1714 |
| exploited-in-the-wild | 1713 |
| threatfox | 1650 |
| high | 1242 |
| medium | 688 |
| malware_download | 578 |

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
