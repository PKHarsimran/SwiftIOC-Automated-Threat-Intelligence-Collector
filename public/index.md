# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-17T17:10:18Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-17T17:10:18Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 24605 |
| Sources reporting | 14 |
| Indicator types | 7 |
| Multi-source overlaps | 3979 |
| Score (min / avg / max) | 60 / 70.3 / 88 |
| High-score indicators (≥80) | 3156 |
| Corroborated (2+ sources) | 3979 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-17T17:09:35Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| url: `hxxp://41[.]216[.]189[.]236/nz[.]sh` | score 88, 2 sources |
| sha256: `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` | score 80, 1 source |
| sha256: `04bc0dbf904d347bfa0b064bb436650fad0583b550dbd9450c8d00f4cb5a3b1b` | score 80, 1 source |
| sha256: `0e8553970999b60c3a0a2637e0c282ca52b33d3e3ae88c99b6fa426bddc0075d` | score 80, 1 source |
| ipv4: `101[.]34[.]222[.]38` | score 80, 1 source |
| ipv4: `102[.]220[.]160[.]105` | score 80, 1 source |
| ipv4: `102[.]220[.]160[.]143` | score 80, 1 source |
| ipv4: `103[.]11[.]41[.]10` | score 80, 1 source |
| ipv4: `103[.]142[.]147[.]18` | score 80, 1 source |
| ipv4: `103[.]186[.]64[.]138` | score 80, 1 source |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5361 |
| greensnow_blocklist | 3458 |
| binarydefense_banlist | 2373 |
| cisa_kev | 1647 |
| threatfox_export_json | 1630 |
| ipsum_level5 | 1578 |
| tor_exit_nodes | 1420 |
| malwarebazaar_recent | 847 |
| et_compromised | 584 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 6322 |
| cve | 1647 |
| domain | 1274 |
| url | 731 |
| sha256 | 12 |
| md5 | 7 |
| sha1 | 7 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 6153 |
| greensnow | 3277 |
| scanner | 2531 |
| ssh | 2396 |
| bruteforce | 2394 |
| binarydefense | 1969 |
| cve | 1647 |
| exploited-in-the-wild | 1647 |
| threatfox | 1591 |
| aggregated | 1506 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 148[.]66[.]142[.]9 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]51 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]52 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]53 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]54 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]55 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]56 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
