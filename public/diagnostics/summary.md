# SwiftIOC IOC Summary

_Generated 2026-10-11T10:31:22Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-10-11T10:31:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6639 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-group overlaps | 365 |
| Score (min / avg / max) | 79 / 80.3 / 96 |
| High-score indicators (≥80) | 9995 |
| 2+ reporting groups | 365 |
| Earliest first_seen | 1997-08-13T04:00:00Z |
| Newest first_seen | 2026-10-11T10:21:12Z |

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
| ipv4: `176[.]65[.]139[.]231` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4633 |
| ipsum_level5 | 4518 |
| binarydefense_banlist | 3489 |
| greensnow_blocklist | 2902 |
| threatfox_export_json | 2338 |
| cisa_kev | 1739 |
| spamhaus_drop | 1684 |
| nist_nvd_recent | 1261 |
| tor_exit_nodes | 1201 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 4091 |
| sha256 | 1777 |
| ipv4_cidr | 1683 |
| url | 951 |
| domain | 871 |
| ipv4 | 207 |
| md5 | 162 |
| sha1 | 161 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| cve | 4091 |
| nvd | 2692 |
| threatfox | 2479 |
| malware | 2238 |
| exploited-in-the-wild | 1739 |
| drop | 1683 |
| spamhaus | 1683 |
| medium | 963 |
| high | 940 |
| Mirai | 827 |

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
