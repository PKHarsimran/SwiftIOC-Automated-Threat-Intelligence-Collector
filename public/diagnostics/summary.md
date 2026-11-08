# SwiftIOC IOC Summary

_Generated 2026-11-08T20:06:38Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-11-08T20:06:38Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 5437 |
| Sources reporting | 17 |
| Indicator types | 8 |
| Multi-group overlaps | 429 |
| Score (min / avg / max) | 80 / 80.4 / 96 |
| High-score indicators (≥80) | 10000 |
| 2+ reporting groups | 429 |
| Earliest first_seen | 2008-09-18T20:00:00Z |
| Newest first_seen | 2026-11-08T20:05:46Z |

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
| blocklist_de_ssh | 4486 |
| ipsum_level5 | 3847 |
| greensnow_blocklist | 2612 |
| threatfox_export_json | 2588 |
| nist_nvd_recent | 2000 |
| urlhaus_recent_urls | 1792 |
| cisa_kev | 1769 |
| spamhaus_drop | 1762 |
| binarydefense_banlist | 1629 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| cve | 2869 |
| sha256 | 2081 |
| url | 2031 |
| ipv4_cidr | 1761 |
| domain | 568 |
| md5 | 266 |
| sha1 | 266 |
| ipv4 | 158 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| malware | 3125 |
| threatfox | 2901 |
| cve | 2869 |
| malware_download | 1792 |
| exploited-in-the-wild | 1769 |
| drop | 1761 |
| spamhaus | 1761 |
| nvd | 1506 |
| None | 962 |
| elf | 674 |

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
