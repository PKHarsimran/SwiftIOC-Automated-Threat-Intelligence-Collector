# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-05T10:29:38Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-05T10:29:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 2607 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 92 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 6955 |
| Corroborated (2+ sources) | 92 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-05T10:29:27Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 3 sources |
| ipv4: `94[.]154[.]43[.]102` | score 93, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4: `39[.]108[.]72[.]32` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5000 |
| greensnow_blocklist | 2411 |
| ipsum_level5 | 1752 |
| spamhaus_drop | 1673 |
| cisa_kev | 1660 |
| binarydefense_banlist | 1554 |
| tor_exit_nodes | 1399 |
| malwarebazaar_recent | 1134 |
| threatfox_export_json | 968 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4004 |
| cve | 2329 |
| ipv4_cidr | 1672 |
| url | 747 |
| domain | 456 |
| ipv4 | 274 |
| md5 | 214 |
| sha1 | 207 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4340 |
| cve | 2329 |
| drop | 1672 |
| spamhaus | 1672 |
| exploited-in-the-wild | 1660 |
| threatfox | 1560 |
| Mirai | 880 |
| nvd | 746 |
| malware_download | 567 |
| high | 402 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
