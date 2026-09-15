# SwiftIOC IOC Summary

_Generated 2026-09-15T09:10:26Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-09-15T09:10:26Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5378 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-source overlaps | 844 |
| Score (min / avg / max) | 80 / 80.6 / 96 |
| High-score indicators (≥80) | 10000 |
| Corroborated (2+ sources) | 844 |
| Earliest first_seen | 2016-05-11T01:59:46Z |
| Newest first_seen | 2026-09-15T09:08:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `77[.]239[.]124[.]108` | score 96, 6 sources |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 sources |
| ipv4: `103[.]176[.]64[.]36` | score 96, 4 sources |
| ipv4: `103[.]182[.]132[.]154` | score 96, 4 sources |
| ipv4: `114[.]111[.]53[.]214` | score 96, 4 sources |
| ipv4: `164[.]90[.]236[.]107` | score 96, 4 sources |
| ipv4: `176[.]65[.]139[.]206` | score 96, 4 sources |
| ipv4: `43[.]129[.]53[.]19` | score 96, 4 sources |
| ipv4: `43[.]156[.]71[.]43` | score 96, 4 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 5163 |
| blocklist_de_ssh | 4924 |
| threatfox_export_json | 4106 |
| binarydefense_banlist | 3899 |
| ipsum_level5 | 2865 |
| nist_nvd_recent | 1851 |
| spamhaus_drop | 1725 |
| cisa_kev | 1710 |
| tor_exit_nodes | 1345 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2697 |
| sha256 | 2322 |
| ipv4_cidr | 1724 |
| domain | 1720 |
| url | 755 |
| sha1 | 352 |
| ipv4 | 286 |
| md5 | 144 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 4181 |
| cve | 2697 |
| malware | 1965 |
| drop | 1724 |
| spamhaus | 1724 |
| exploited-in-the-wild | 1710 |
| nvd | 1233 |
| rat | 973 |
| asyncrat | 951 |
| Sepolia | 924 |

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
