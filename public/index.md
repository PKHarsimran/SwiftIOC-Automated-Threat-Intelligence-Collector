# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-11T08:48:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-11T08:48:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3489 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 128 |
| Score (min / avg / max) | 78 / 79.9 / 96 |
| High-score indicators (≥80) | 7583 |
| Corroborated (2+ sources) | 128 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-11T08:38:31Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `91[.]92[.]40[.]5` | score 96, 5 sources |
| ipv4: `94[.]154[.]43[.]77` | score 96, 5 sources |
| ipv4: `5[.]61[.]209[.]44` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]249` | score 96, 4 sources |
| ipv4: `94[.]154[.]43[.]46` | score 96, 3 sources |
| ipv4: `130[.]12[.]180[.]51` | score 88, 2 sources |
| ipv4_cidr: `195.178.110.0/24` | score 88, 2 sources |
| ipv4_cidr: `204.76.203.0/24` | score 88, 2 sources |
| ipv4_cidr: `213.209.159.0/24` | score 88, 2 sources |
| ipv4_cidr: `43.228.157.0/24` | score 88, 2 sources |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 10405 |
| greensnow_blocklist | 3709 |
| binarydefense_banlist | 3036 |
| ipsum_level5 | 2092 |
| spamhaus_drop | 1687 |
| cisa_kev | 1662 |
| malwarebazaar_recent | 1628 |
| tor_exit_nodes | 1382 |
| threatfox_export_json | 835 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3998 |
| cve | 2512 |
| ipv4_cidr | 1686 |
| url | 676 |
| domain | 447 |
| md5 | 205 |
| ipv4 | 199 |
| sha1 | 180 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4308 |
| cve | 2512 |
| drop | 1686 |
| spamhaus | 1686 |
| exploited-in-the-wild | 1662 |
| threatfox | 1397 |
| Mirai | 1360 |
| nvd | 958 |
| malware_download | 517 |
| high | 438 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 91[.]92[.]40[.]5 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]77 | binarydefense_banlist, blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 5[.]61[.]209[.]44 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]249 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 94[.]154[.]43[.]46 | binarydefense_banlist, ipsum_level5, threatfox_export_json |
| cve: CVE-2009-3960 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1710 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-1723 | cisa_kev, nist_nvd_recent |
| cve: CVE-2012-4681 | cisa_kev, nist_nvd_recent |
| cve: CVE-2015-2291 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
