# SwiftIOC IOC Summary

_Generated 2026-10-12T11:48:40Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-12T11:48:40Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7124 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-group overlaps | 371 |
| Score (min / avg / max) | 79 / 80.3 / 96 |
| High-score indicators (≥80) | 9801 |
| 2+ reporting groups | 371 |
| Earliest first_seen | 2002-10-04T04:00:00Z |
| Newest first_seen | 2026-10-12T11:36:19Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]60` | score 96, 5 reporting groups |
| ipv4: `94[.]154[.]43[.]69` | score 96, 5 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `36[.]50[.]134[.]86` | score 96, 3 reporting groups |
| ipv4: `45[.]17[.]39[.]120` | score 96, 3 reporting groups |
| ipv4: `45[.]198[.]224[.]184` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `165[.]245[.]160[.]178` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| ipsum_level5 | 4723 |
| blocklist_de_ssh | 4715 |
| greensnow_blocklist | 4339 |
| binarydefense_banlist | 3698 |
| cisa_kev | 1739 |
| spamhaus_drop | 1677 |
| threatfox_export_json | 1621 |
| nist_nvd_recent | 1302 |
| tor_exit_nodes | 1201 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 3944 |
| sha256 | 1885 |
| ipv4_cidr | 1676 |
| url | 1534 |
| domain | 313 |
| ipv4 | 262 |
| md5 | 145 |
| sha1 | 144 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 3944 |
| malware | 2901 |
| nvd | 2546 |
| threatfox | 1926 |
| exploited-in-the-wild | 1739 |
| drop | 1676 |
| spamhaus | 1676 |
| malware_download | 1174 |
| medium | 1107 |
| Mirai | 869 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]60 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]69 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 36[.]50[.]134[.]86 | blocklist_de_ssh, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]17[.]39[.]120 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]184 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]198[.]224[.]34 | et_compromised, ipsum_level5, threatfox_export_json |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
