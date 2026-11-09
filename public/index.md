# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-11-09T04:18:25Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-09T04:18:25Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 6175 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 429 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 429 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-09T04:17:07Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| ipv4: `130[.]12[.]180[.]32` | score 96, 5 reporting groups |
| ipv4: `91[.]92[.]43[.]221` | score 96, 4 reporting groups |
| ipv4: `114[.]111[.]53[.]214` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]162[.]74` | score 96, 3 reporting groups |
| ipv4: `165[.]154[.]227[.]8` | score 96, 3 reporting groups |
| ipv4: `176[.]65[.]139[.]131` | score 96, 3 reporting groups |
| ipv4: `45[.]78[.]201[.]248` | score 96, 3 reporting groups |
| ipv4: `45[.]90[.]163[.]37` | score 96, 3 reporting groups |
| ipv4: `77[.]239[.]124[.]135` | score 96, 3 reporting groups |
| ipv4: `158[.]220[.]81[.]103` | score 88, 2 reporting groups |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4571 |
| ipsum_level5 | 3884 |
| greensnow_blocklist | 3240 |
| threatfox_export_json | 3032 |
| binarydefense_banlist | 1920 |
| urlhaus_recent_urls | 1888 |
| cisa_kev | 1769 |
| spamhaus_drop | 1762 |
| nist_nvd_recent | 1527 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2680 |
| url | 2186 |
| sha256 | 1891 |
| ipv4_cidr | 1759 |
| domain | 984 |
| md5 | 172 |
| sha1 | 172 |
| ipv4 | 156 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3317 |
| threatfox | 2994 |
| cve | 2680 |
| malware_download | 1888 |
| exploited-in-the-wild | 1769 |
| drop | 1759 |
| spamhaus | 1759 |
| nvd | 1317 |
| None | 949 |
| ClickFix | 901 |

## Multi-group reporting overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 130[.]12[.]180[.]32 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 91[.]92[.]43[.]221 | blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 114[.]111[.]53[.]214 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]162[.]74 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 165[.]154[.]227[.]8 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 176[.]65[.]139[.]131 | blocklist_de_ssh, et_compromised, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]78[.]201[.]248 | blocklist_de_ssh, greensnow_blocklist, ipsum_level5, threatfox_export_json |
| ipv4: 45[.]90[.]163[.]37 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| ipv4: 77[.]239[.]124[.]135 | binarydefense_banlist, ci_army_list, ipsum_level5, threatfox_export_json |
| cve: CVE-2008-4128 | cisa_kev, nist_nvd_recent |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
