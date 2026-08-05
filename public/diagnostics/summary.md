# SwiftIOC IOC Summary

_Generated 2026-08-05T02:02:22Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-05T02:02:22Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3059 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 84 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 8729 |
| Corroborated (2+ sources) | 84 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-05T01:52:20Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]102` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 3 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4: `39[.]108[.]72[.]32` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5057 |
| greensnow_blocklist | 3555 |
| ipsum_level5 | 1752 |
| spamhaus_drop | 1665 |
| cisa_kev | 1660 |
| binarydefense_banlist | 1554 |
| tor_exit_nodes | 1402 |
| malwarebazaar_recent | 992 |
| threatfox_export_json | 968 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4072 |
| cve | 2354 |
| ipv4_cidr | 1664 |
| url | 649 |
| domain | 430 |
| md5 | 253 |
| sha1 | 245 |
| ipv4 | 236 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4298 |
| cve | 2354 |
| drop | 1664 |
| spamhaus | 1664 |
| exploited-in-the-wild | 1660 |
| threatfox | 1584 |
| Mirai | 886 |
| nvd | 764 |
| malware_download | 492 |
| high | 411 |

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
