# SwiftIOC IOC Summary

_Generated 2026-07-30T10:21:02Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-30T10:21:02Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2244 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 24 |
| Score (min / avg / max) | 79 / 80.0 / 96 |
| High-score indicators (≥80) | 9816 |
| Corroborated (2+ sources) | 24 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-07-30T10:14:26Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4: `217[.]60[.]195[.]187` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 9419 |
| threatfox_export_json | 3177 |
| greensnow_blocklist | 2393 |
| spamhaus_drop | 1667 |
| cisa_kev | 1656 |
| binarydefense_banlist | 1512 |
| tor_exit_nodes | 1376 |
| ipsum_level5 | 1275 |
| malwarebazaar_recent | 857 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2450 |
| sha256 | 1981 |
| domain | 1770 |
| ipv4_cidr | 1666 |
| url | 802 |
| md5 | 532 |
| ipv4 | 425 |
| sha1 | 277 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3394 |
| cve | 2450 |
| malware | 2392 |
| drop | 1666 |
| spamhaus | 1666 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1353 |
| nvd | 804 |
| Mac | 688 |
| malware_download | 676 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2024-30088 | cisa_kev, nist_nvd_recent |
| cve: CVE-2024-35250 | cisa_kev, nist_nvd_recent |
| cve: CVE-2025-68686 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-0770 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-31431 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-45498 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-5281 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
