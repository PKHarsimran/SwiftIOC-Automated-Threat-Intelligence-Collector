# SwiftIOC IOC Summary

_Generated 2026-10-12T03:59:22Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-12T03:59:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 7757 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-group overlaps | 366 |
| Score (min / avg / max) | 79 / 80.2 / 96 |
| High-score indicators (≥80) | 9176 |
| 2+ reporting groups | 366 |
| Earliest first_seen | 2002-10-04T04:00:00Z |
| Newest first_seen | 2026-10-12T03:51:15Z |

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
| ipv4: `156[.]225[.]17[.]60` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| greensnow_blocklist | 4803 |
| blocklist_de_ssh | 4743 |
| ipsum_level5 | 4723 |
| binarydefense_banlist | 3698 |
| cisa_kev | 1739 |
| spamhaus_drop | 1684 |
| threatfox_export_json | 1512 |
| nist_nvd_recent | 1241 |
| tor_exit_nodes | 1197 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4398 |
| sha256 | 1942 |
| ipv4_cidr | 1683 |
| url | 1057 |
| domain | 248 |
| ipv4 | 210 |
| md5 | 183 |
| sha1 | 182 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4398 |
| nvd | 3000 |
| malware | 2370 |
| threatfox | 2090 |
| exploited-in-the-wild | 1739 |
| drop | 1683 |
| spamhaus | 1683 |
| medium | 1258 |
| high | 973 |
| Mirai | 935 |

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
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
