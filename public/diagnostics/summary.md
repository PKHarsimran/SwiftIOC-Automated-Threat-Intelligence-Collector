# SwiftIOC IOC Summary

_Generated 2026-08-07T00:51:26Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-07T00:51:26Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3002 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 105 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 7447 |
| Corroborated (2+ sources) | 105 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-07T00:40:04Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.142.193.0/24` | score 88, 2 sources |
| ipv4_cidr: `45.148.10.0/24` | score 88, 2 sources |
| ipv4_cidr: `77.90.185.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 9829 |
| greensnow_blocklist | 4230 |
| binarydefense_banlist | 2111 |
| spamhaus_drop | 1682 |
| ipsum_level5 | 1680 |
| cisa_kev | 1661 |
| tor_exit_nodes | 1391 |
| malwarebazaar_recent | 1162 |
| threatfox_export_json | 1048 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4370 |
| cve | 2297 |
| ipv4_cidr | 1681 |
| domain | 583 |
| url | 469 |
| ipv4 | 255 |
| md5 | 136 |
| sha1 | 112 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4632 |
| cve | 2297 |
| drop | 1681 |
| spamhaus | 1681 |
| exploited-in-the-wild | 1661 |
| threatfox | 1290 |
| Mirai | 1158 |
| nvd | 728 |
| high | 482 |
| malware_download | 404 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]102 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
