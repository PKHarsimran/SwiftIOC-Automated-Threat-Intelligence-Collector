# SwiftIOC Threat Intelligence Snapshot

This site is generated automatically from the latest SwiftIOC collection run.

_Generated 2026-07-19T02:12:20Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-19T02:12:20Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 4216 |
| Sources reporting | 15 |
| Indicator types | 8 |
| Multi-source overlaps | 4430 |
| Score (min / avg / max) | 68 / 75.5 / 88 |
| High-score indicators (≥80) | 4150 |
| Corroborated (2+ sources) | 4430 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-19T02:11:47Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| url: `hxxp://41[.]216[.]189[.]236/nz[.]sh` | score 88, 2 sources |
| sha256: `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` | score 80, 1 source |
| sha1: `0301c109feb04625b760b29cc34fceadd8c62e6f` | score 80, 1 source |
| md5: `036227aa4ccacd6153de68143e02f001` | score 80, 1 source |
| sha1: `044b9e2eba3cb9c410aff01e350676b2405c930e` | score 80, 1 source |
| sha256: `04bc0dbf904d347bfa0b064bb436650fad0583b550dbd9450c8d00f4cb5a3b1b` | score 80, 1 source |
| md5: `057739a12fa0d25a1017e5f7a8538140` | score 80, 1 source |
| sha256: `06ba715b44892af143c4336c189c28b5d95f446d3d07ca7ce7a6ab2a0601168b` | score 80, 1 source |
| sha1: `0a07b70b37919c01cfddd5e4b4260b144e138ac5` | score 80, 1 source |
| md5: `0a9a59c9e53e6d9f218fc6c307016b44` | score 80, 1 source |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 5534 |
| greensnow_blocklist | 3775 |
| binarydefense_banlist | 2819 |
| ipsum_level5 | 2279 |
| spamhaus_drop | 1678 |
| cisa_kev | 1647 |
| tor_exit_nodes | 1422 |
| threatfox_export_json | 888 |
| malwarebazaar_recent | 692 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4681 |
| ipv4_cidr | 1677 |
| cve | 1647 |
| domain | 1527 |
| url | 340 |
| sha256 | 46 |
| md5 | 41 |
| sha1 | 41 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 4429 |
| aggregated | 2990 |
| ipsum | 2990 |
| multi-list | 2990 |
| scanner | 2856 |
| cins | 2358 |
| threatfox | 2242 |
| ssh | 1932 |
| bruteforce | 1930 |
| binarydefense | 1815 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 107[.]189[.]10[.]124 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 148[.]66[.]142[.]9 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 151[.]217[.]4[.]34 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 159[.]65[.]143[.]47 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]49 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]51 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
