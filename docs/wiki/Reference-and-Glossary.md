# Reference and glossary

## Output map

Paths are under the configured output directory (usually `public/`). Some generated formats are ignored by Git and created during collection/deployment.

| Path | Purpose |
| --- | --- |
| `iocs/latest.csv`, `.tsv`, `.json`, `.jsonl` | Full retained compatibility snapshot. |
| `iocs/dashboard.jsonl` | Compact browser preview (default maximum 1,000 rows). |
| `iocs/high_confidence.csv`, `.jsonl` | Score-threshold or multi-source subset. |
| `iocs/delta.json`, `.jsonl` | Latest snapshot comparison: envelope and event stream. |
| `iocs/stix2.json` | STIX 2.1 bundle; CVEs use vulnerability objects. |
| `collections/` | Separate observable and vulnerability collections. |
| `misp/` | MISP event feed and manifest. |
| `detections/` | Sigma, Suricata, RPZ and verification manifest. |
| `diagnostics/run.json` | Published run statistics and baseline metadata. |
| `diagnostics/collection-attempt.json` | Quality-phase outcome for the most recent attempt. |
| `diagnostics/REPORT.md`, `summary.md` | Human-readable operational reports. |
| `feed.xml`, `badge.json` | RSS and dynamic snapshot badge. |
| `history_summary.json` | Compact historical summary derived from Git. |
| `signatures/` | Separate-workflow Sigstore bundles for canonical feeds. |

## CLI options

The exact installed interface is always available with:

```bash
python -m swiftioc --help
python -m swiftioc.verify_detections --help
```

| Group | Options |
| --- | --- |
| Inputs / collection | `--sources`, `--window-hours`, `--source-window`, `--skip-rss`, `--max-workers`, `--max-per-source`, `--urlhaus-status`, `--grace-on-404` |
| Data policy | `--no-fp-filter`, `--persist-feed`, `--min-score`, `--max-age-days`, `--max-store`, `--high-confidence-score` |
| Quality gates | `--fail-on-empty`, `--fail-if-stale`, `--fail-if-volume-drop`, `--warn-if-volume-drop` |
| Output | `--out-dir`, `--dashboard-rows`, `--site-url`, `--rss-limit`, `--no-misp-feed` |
| Diagnostics | `--diag-json`, `--report`, `-v` / `--verbose`, `--log-file`, `--log-format`, `--log-file-level`, `--save-raw-dir` |
| Runtime / checks | `--ua-file`, `--ci-safe`, `--self-test`, `-h` / `--help` |

See [Operations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Operations-and-Troubleshooting) for gate semantics, [Data and scoring](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Data-and-Scoring) for defaults, and [Sources](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Sources-and-Parsers) for configuration. Repeated name/value options use `source_name=VALUE`. Use the installed help for accepted values rather than copying a flag from a newer version.

## Glossary

| Term | Plain-language meaning |
| --- | --- |
| IOC / observable | A value such as an IP, domain, URL or hash used as an investigative lead. |
| CVE | Identifier for a cataloged vulnerability, not a telemetry indicator by itself. |
| KEV | CISA catalog evidence that a vulnerability is known to be exploited. |
| NVD | Vulnerability metadata including severity and applicability information. |
| CPE | Structured product identity used in applicability criteria. |
| CVSS | Severity scoring; not proof of exploitation or local exposure. |
| Defang / refang | Make a value less likely to be opened accidentally / restore its ordinary spelling for matching. |
| Provenance | Where evidence came from and the context/timestamps supporting it. |
| Source / provider | An adapter/feed identifier / the organization or reporting entity behind feeds. |
| Corroboration | More than one report; independence must be evaluated separately. |
| Retention | Rules limiting which records remain published. |
| Baseline / Delta | Prior usable snapshot / changes relative to it. |
| SPL | Splunk Search Processing Language. |
| Sigma | Portable detection-rule format requiring backend-specific conversion. |
| Suricata SID | Stable identifier for a Suricata rule. |
| RPZ | DNS Response Policy Zone used to alter answers according to policy. |
| STIX / TAXII | Threat-data representation / exchange protocol; a TAXII-shaped file is not a server. |
| TLP | Traffic Light Protocol handling designation; also respect original provider conditions. |

## Keep this Wiki current

The Wiki is a separate Git repository from the project. The main-repository `docs/wiki/` files are reviewable source copies, not an automatic publishing system. Keep the copies and published pages in sync when behavior changes.

1. Review changed code, tests, CLI help and workflows.
2. Update the relevant source pages and “reviewed against” commit/date.
3. Check internal links, Mermaid syntax and media; provide static alternatives for animation.
4. Publish pages through the Wiki editor or its Git remote.
5. Verify the rendered pages and navigation after publishing.

Clone the initialized Wiki separately if you have Git write access:

```bash
git clone https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector.wiki.git
```

Wiki images in this edition use immutable repository-commit URLs so removing a feature branch does not break them. The optional animations are GIFs; static equivalents explain the same steps. GitHub Wiki renders Mermaid diagrams but does not provide a custom JavaScript application runtime. For current project behavior, source and regression tests take precedence over prose.

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
