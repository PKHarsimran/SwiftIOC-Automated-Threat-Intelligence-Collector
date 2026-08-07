# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-07T20:35:06Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-07T20:35:06Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3008 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 109 |
| Score (min / avg / max) | 79 / 79.8 / 96 |
| High-score indicators (≥80) | 7312 |
| Corroborated (2+ sources) | 109 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-07T20:22:07Z |

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
| blocklist_de_ssh | 9092 |
| greensnow_blocklist | 3445 |
| binarydefense_banlist | 2111 |
| ipsum_level5 | 2004 |
| spamhaus_drop | 1683 |
| cisa_kev | 1662 |
| threatfox_export_json | 1402 |
| tor_exit_nodes | 1388 |
| malwarebazaar_recent | 1031 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 4372 |
| cve | 2021 |
| ipv4_cidr | 1682 |
| domain | 728 |
| url | 601 |
| ipv4 | 231 |
| md5 | 146 |
| sha1 | 122 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4774 |
| cve | 2021 |
| drop | 1682 |
| spamhaus | 1682 |
| exploited-in-the-wild | 1662 |
| threatfox | 1425 |
| Mirai | 1126 |
| malware_download | 540 |
| nvd | 453 |
| ClearFake | 363 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-12615 | cisa_kev, nist_nvd_recent |
| cve: CVE-2017-6884 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
