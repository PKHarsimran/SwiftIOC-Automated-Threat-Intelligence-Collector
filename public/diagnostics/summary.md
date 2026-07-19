# SwiftIOC IOC Summary

_Generated 2026-07-19T16:52:54Z_

## Highlights

| Metric | Value |
| --- | ---: |
| Generated | 2026-07-19T16:52:54Z |
| Window (hours) | 48 |
| Total indicators | 10000 |
| Duplicates removed | 3472 |
| Sources reporting | 15 |
| Indicator types | 8 |
| Multi-source overlaps | 4348 |
| Score (min / avg / max) | 68 / 75.3 / 88 |
| High-score indicators (≥80) | 4204 |
| Corroborated (2+ sources) | 4348 |
| Earliest first_seen | 2021-11-03T00:00:00Z |
| Newest first_seen | 2026-07-19T16:52:47Z |

## Top indicators by score

| Indicator | Score / corroboration |
| --- | ---: |
| url: `hxxp://103[.]83[.]87[.]122/telnet[.]sh` | score 88, 2 sources |
| url: `hxxps://gerenland[.]click/api/stale[.]msi` | score 88, 2 sources |
| url: `hxxps://gerenland[.]click/flask/whales[.]msi` | score 88, 2 sources |
| url: `hxxp://41[.]216[.]189[.]236/nz[.]sh` | score 84, 2 sources |
| sha256: `02e6fbf7319629a352755bded9ec28dfdaffc0affb7c1a7de9a1b3b69bd91de5` | score 80, 1 source |
| sha1: `0301c109feb04625b760b29cc34fceadd8c62e6f` | score 80, 1 source |
| md5: `036227aa4ccacd6153de68143e02f001` | score 80, 1 source |
| sha1: `044b9e2eba3cb9c410aff01e350676b2405c930e` | score 80, 1 source |
| sha256: `04bc0dbf904d347bfa0b064bb436650fad0583b550dbd9450c8d00f4cb5a3b1b` | score 80, 1 source |
| md5: `057739a12fa0d25a1017e5f7a8538140` | score 80, 1 source |

## Per-source totals

| Source | Indicators |
| --- | ---: |
| ci_army_list | 15000 |
| blocklist_de_ssh | 4974 |
| greensnow_blocklist | 2893 |
| binarydefense_banlist | 2819 |
| ipsum_level5 | 2279 |
| spamhaus_drop | 1678 |
| cisa_kev | 1647 |
| tor_exit_nodes | 1423 |
| threatfox_export_json | 949 |
| malwarebazaar_recent | 657 |

## Indicator types

| Type | Indicators |
| --- | ---: |
| ipv4 | 4593 |
| ipv4_cidr | 1677 |
| cve | 1647 |
| domain | 1615 |
| url | 326 |
| sha256 | 60 |
| md5 | 41 |
| sha1 | 41 |

## Top tags

| Tag | Indicators |
| --- | ---: |
| blocklist | 4344 |
| aggregated | 2854 |
| ipsum | 2854 |
| multi-list | 2854 |
| scanner | 2774 |
| threatfox | 2327 |
| cins | 2273 |
| ssh | 1986 |
| bruteforce | 1983 |
| binarydefense | 1848 |

## Multi-source overlaps

| Indicator | Sources |
| --- | --- |
| ipv4: 154[.]90[.]70[.]254 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 101[.]47[.]15[.]119 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 107[.]189[.]10[.]124 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 118[.]216[.]88[.]229 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, et_compromised, ipsum_level5 |
| ipv4: 118[.]26[.]111[.]107 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 144[.]31[.]156[.]249 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 148[.]66[.]142[.]9 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 151[.]217[.]4[.]34 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |
| ipv4: 159[.]65[.]143[.]47 | blocklist_de_ssh, ci_army_list, et_compromised, greensnow_blocklist, ipsum_level5 |
| ipv4: 167[.]94[.]146[.]49 | binarydefense_banlist, blocklist_de_ssh, ci_army_list, greensnow_blocklist, ipsum_level5 |

For more detail see [diagnostics/REPORT.md](diagnostics/REPORT.md) and the machine-readable feeds in [iocs/](iocs/).
