# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-08-11T12:52:38Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-08-11T12:52:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3328 |
| Sources reporting | 17 |
| Indicator types | 9 |
| Multi-source overlaps | 126 |
| Score (min / avg / max) | 79 / 79.9 / 96 |
| High-score indicators (≥80) | 8271 |
| Corroborated (2+ sources) | 126 |
| Earliest first_seen | 2017-07-14T18:08:15Z |
| Newest first_seen | 2026-08-11T12:52:18Z |

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
| blocklist_de_ssh | 10504 |
| greensnow_blocklist | 3156 |
| binarydefense_banlist | 3036 |
| ipsum_level5 | 2092 |
| malwarebazaar_recent | 1837 |
| spamhaus_drop | 1687 |
| cisa_kev | 1662 |
| tor_exit_nodes | 1381 |
| threatfox_export_json | 906 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| sha256 | 3749 |
| cve | 2276 |
| ipv4_cidr | 1687 |
| url | 1125 |
| domain | 492 |
| ipv4 | 237 |
| md5 | 181 |
| sha1 | 156 |
| ja3 | 97 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 4534 |
| cve | 2276 |
| drop | 1687 |
| spamhaus | 1687 |
| exploited-in-the-wild | 1662 |
| threatfox | 1404 |
| Mirai | 1291 |
| malware_download | 965 |
| nvd | 722 |
| elf | 568 |

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
