# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-09-10T02:00:07Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-10T02:00:07Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6286 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 539 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 539 |
| Earliest first_seen | 2019-07-15T19:15:16Z |
| Newest first_seen | 2026-09-10T01:52:44Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |
| ipv4: `45[.]17[.]39[.]120` | score 96, 4 sources |
| ipv4: `68[.]233[.]116[.]124` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]69` | score 95, 3 sources |
| sha256: `00147abaca1263e02190ac12e15ab0db45bf250ef2dae53e945a9d8b40c01598` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5210 |
| blocklist_de_ssh | 4932 |
| ipsum_level5 | 3889 |
| threatfox_export_json | 2757 |
| binarydefense_banlist | 2650 |
| nist_nvd_recent | 2600 |
| spamhaus_drop | 1709 |
| cisa_kev | 1703 |
| tor_exit_nodes | 1337 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4046 |
| domain | 1965 |
| ipv4_cidr | 1708 |
| sha256 | 1137 |
| url | 562 |
| ipv4 | 296 |
| sha1 | 247 |
| md5 | 39 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4046 |
| threatfox | 2864 |
| nvd | 2577 |
| drop | 1708 |
| spamhaus | 1708 |
| exploited-in-the-wild | 1703 |
| malware | 1666 |
| etherhiding | 1401 |
| high | 1156 |
| Sepolia | 829 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 77[.]239[.]124[.]108 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 103[.]176[.]64[.]36 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 164[.]90[.]236[.]107 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]129[.]53[.]19 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 43[.]156[.]71[.]43 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 68[.]233[.]116[.]124 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | blocklist_de_ssh, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
