# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-31T02:22:05Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-31T02:22:05Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3137 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 25 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 8793 |
| Corroborated (2+ sources) | 25 |
| Earliest first_seen | 2013-04-12T22:55:01Z |
| Newest first_seen | 2026-07-31T02:15:50Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4: `217[.]60[.]195[.]187` | score 96, 3 sources |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 9388 |
| greensnow_blocklist | 3760 |
| threatfox_export_json | 2988 |
| ipsum_level5 | 1780 |
| binarydefense_banlist | 1758 |
| spamhaus_drop | 1667 |
| cisa_kev | 1656 |
| tor_exit_nodes | 1371 |
| malwarebazaar_recent | 847 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2302 |
| sha256 | 2188 |
| domain | 1785 |
| ipv4_cidr | 1666 |
| url | 685 |
| md5 | 548 |
| ipv4 | 414 |
| sha1 | 315 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| threatfox | 3443 |
| malware | 2492 |
| cve | 2302 |
| drop | 1666 |
| spamhaus | 1666 |
| exploited-in-the-wild | 1656 |
| ClickFix | 1344 |
| Mac | 687 |
| c2 | 666 |
| nvd | 656 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 217[.]60[.]195[.]187 | binarydefense_banlist, blocklist_de_ssh, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2024-30088 | cisa_kev, nist_nvd_recent |
| cve: CVE-2024-35250 | cisa_kev, nist_nvd_recent |
| cve: CVE-2025-68686 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-0770 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-31431 | cisa_kev, nist_nvd_recent |
| cve: CVE-2026-45498 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
