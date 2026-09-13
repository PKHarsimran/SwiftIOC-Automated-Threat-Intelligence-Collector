# SwiftIOC IOC Summary

_Generated 2026-09-13T22:02:06Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-13T22:02:06Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6538 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 792 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 792 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-13T21:54:28Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 11484 |
| ipsum_level5 | 4677 |
| threatfox_export_json | 4111 |
| greensnow_blocklist | 3991 |
| binarydefense_banlist | 3373 |
| spamhaus_drop | 1725 |
| cisa_kev | 1709 |
| tor_exit_nodes | 1324 |
| et_compromised | 610 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3383 |
| cve | 2752 |
| ipv4_cidr | 1724 |
| domain | 579 |
| url | 575 |
| sha1 | 418 |
| ipv4 | 314 |
| md5 | 210 |
| ja3 | 45 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4584 |
| cve | 2752 |
| rat | 2375 |
| asyncrat | 2373 |
| drop | 1724 |
| spamhaus | 1724 |
| exploited-in-the-wild | 1709 |
| malware | 1409 |
| nvd | 1287 |
| high | 529 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]182[.]132[.]154 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]206 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
