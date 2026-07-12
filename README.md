# ⚡ SwiftIOC – Open Source Automated Threat Intelligence Collector

[![CI – SwiftIOC](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/ci.yml/badge.svg)](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/ci.yml)
[![CodeQL](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/codeql.yml/badge.svg)](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/codeql.yml)
[![Security Policy](https://img.shields.io/badge/security-SECURITY.md-informational)](./SECURITY.md)

SwiftIOC is an open-source Python threat intelligence automation toolkit that
keeps recent Indicators of Compromise (IOCs) in machine-readable formats. The
lightweight collector (`swiftioc.py`) ingests threat feeds via YAML
configuration, normalises and deduplicates the indicators, and exports them to
CSV, TSV, JSON, JSON Lines, and STIX 2.1 alongside searchable run diagnostics.

Designed for security operations teams, SOC analysts, and cyber threat hunters,
SwiftIOC runs anywhere Python is available—local workstations, CI/CD pipelines,
GitHub Actions, or automated cron jobs. Outputs land under `public/` by default
so they can be published directly with GitHub Pages, integrated into SIEM and
SOAR tooling, or archived for compliance reporting. The repository includes
ready-to-use examples for rapid deployment in modern DevSecOps workflows.

## 📚 Table of contents
- [SwiftIOC at a glance](#-swiftioc-at-a-glance)
- [Features](#-features)
- [GitHub project health](#-github-project-health)
- [Supported threat intelligence sources](#-supported-threat-intelligence-sources)
- [Use cases & SEO-friendly keywords](#-use-cases--seo-friendly-keywords)
- [Repository layout](#-repository-layout)
- [How it works](#-how-it-works)
- [Indicator scoring & the living feed](#-indicator-scoring--the-living-feed)
- [Quick start](#-quick-start)
- [Configuring sources](#-configuring-sources)
- [CLI reference](#-cli-reference)
- [Outputs & diagnostics](#-outputs--diagnostics)
- [Running in GitHub Actions](#-running-in-github-actions)
- [GitHub Pages preview & publishing](#-github-pages-preview--publishing)
- [Auto-generated IOC summary](#auto-generated-ioc-summary)

## 🔍 SwiftIOC at a glance
SwiftIOC helps cybersecurity teams automate the collection and publication of
high-fidelity IOCs from authoritative sources. The project emphasises:

- **Automated threat feed aggregation** with YAML-based configuration.
- **Consistent IOC enrichment** ready for SIEM, SOAR, IDS, and DFIR tooling.
- **Git-friendly artefacts** tailored for GitHub Pages, GitHub Actions, and
  other CI/CD environments.

## 🚀 Features
- **YAML-driven feeds** – feed metadata lives in `sources.yml` so collections can
  be changed without touching Python code. The example file includes adapters for
  CISA KEV, URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, SSLBL JA3, Spamhaus
  DROP, OpenPhish, CINS Army, and Tor exit lists.
- **Indicator normalisation** – every indicator is represented by the
  `Indicator` dataclass and classified (IPv4/IPv6, URL, domain, hash, CVE, etc.)
  before being written to disk. 
- **Defanging & deduplication** – helper functions defang URLs/domains and
  remove duplicate indicators so that downstream tools receive safe, unique
  values. Host casing is normalised before dedup so `Evil.COM` and `evil.com`
  collapse to one record.
- **False-positive filtering** – bogon IP ranges (private, loopback,
  link-local, reserved, multicast) and well-known benign hosts (`example.com`,
  `localhost`, `*.test`, …) are dropped automatically; disable with
  `--no-fp-filter`. The count is reported in diagnostics.
- **Indicator scoring, decay & a living feed** – every indicator gets a 0–100
  relevance score combining source confidence, cross-source corroboration
  (independent feeds agreeing boosts the score), and age-based exponential
  decay with per-type half-lives. With `--persist-feed` the collector merges
  the previously published feed each run: re-observed indicators refresh to
  full score, unobserved ones fade out, and entries below `--min-score`
  expire. Most free aggregators publish stale snapshots — SwiftIOC publishes
  a self-maintaining feed.
- **Curated high-confidence feed** – alongside the full exports, every run emits
  `high_confidence.csv`/`.jsonl` containing only indicators that score ≥80 or
  are confirmed by 2+ independent sources, strongest-first. This is the
  block-ready subset for SIEM/firewall ingestion where false positives are
  costly.
- **Concurrent collection** – sources are fetched in parallel (configurable via
  `--max-workers`), so a full run completes in a fraction of the time of a
  sequential fetch without changing the deterministic output.
- **Multiple export formats** – each run emits CSV, TSV, JSON, JSON Lines, a
  STIX 2.1 bundle, and a Markdown changelog. The STIX bundle covers every
  indicator type (IPs and CIDRs, domains, URLs, all hash sizes, emails, JA3/JA3S,
  wallets) with deterministic RFC 4122 UUIDs, a producer `identity`, and a TLP
  marking, so re-imports stay idempotent in MISP, OpenCTI, and similar platforms.
  CVEs are emitted as `vulnerability` objects. The changelog is capped to the
  most recent runs to keep it committable indefinitely.
- **Rich diagnostics** – a JSON run summary, Markdown report, and per-source
  counts are generated automatically for audits and dashboards. 
- **Optional RSS collection** – RSS feeds are processed when `feedparser` is
  installed; use `--skip-rss` (or `--ci-safe`) to run without the dependency.
- **CI-friendly defaults** – JSON logging, deterministic output paths, and
  guard-rail flags (`--fail-on-empty`, `--fail-if-stale`, `--grace-on-404`) make
  the collector predictable in automation.

## 🛡️ GitHub project health
- **Continuous integration** – the `CI – SwiftIOC` workflow lint-checks the
  Python codebase, validates types, audits dependencies, and exercises the
  collector end-to-end on every push and pull request.
- **CodeQL scanning** – GitHub's CodeQL workflow analyses the repository for
  common security issues to keep the collector safe for automation.
- **Security policy** – coordinated vulnerability disclosures are handled via
  [`SECURITY.md`](SECURITY.md) with direct contact guidance for maintainers.

## 🌐 Supported threat intelligence sources
SwiftIOC ships with parsers and adapters for widely referenced cyber threat
intelligence feeds used by SOC teams and managed security providers:

- **CISA Known Exploited Vulnerabilities (KEV)** – prioritise patching by
  monitoring the official CISA KEV catalogue.
- **URLhaus** – ingest malicious URL indicators to protect web gateways and
  proxies.
- **MalwareBazaar** – track malicious file hashes for EDR, AV, and sandbox
  tooling.
- **ThreatFox** – add IPs, domains, URLs, and hashes curated by abuse.ch.
- **Feodo Tracker & SSLBL JA3 fingerprints** – detect C2 traffic associated
  with banking trojans and malicious TLS fingerprints.
- **Spamhaus DROP/EDROP** – block known botnet controllers at the network edge.
- **OpenPhish, CINS Army, Tor exit lists, and more** – extend coverage with
  phishing, scanning, and anonymiser indicators.

Each feed is configurable through `sources.yml`, allowing teams to fine-tune the
collection cadence, lookback windows, and authentication as required.

## 🎯 Use cases & SEO-friendly keywords
SwiftIOC supports a wide range of cybersecurity automation workflows. Common
use cases include:

- **Security Operations Centre (SOC) automation** – schedule IOC collection
  jobs to keep SIEM and IDS rules current with open-source threat intelligence.
- **Digital forensics & incident response (DFIR)** – export defanged indicators
  for investigations without risking accidental activation.
- **DevSecOps pipelines** – integrate threat feed enrichment into CI/CD, GitOps,
  or infrastructure-as-code projects.
- **Threat hunting playbooks** – generate STIX 2.1 bundles consumable by MISP,
  OpenCTI, and other CTI platforms.
- **Compliance reporting and executive dashboards** – leverage Markdown and
  JSON diagnostics for stakeholder-friendly reporting.

Keywords to improve discoverability: "automated threat intelligence collector",
"open source IOC feed aggregator", "Python threat hunting toolkit", "cyber
threat intelligence automation", "STIX export for SOC", and "GitHub Actions
threat feed workflow".

## 🗂️ Repository layout
```
├── public/                 # Default output directory for generated feeds
│   ├── iocs/               # CSV, JSON, JSONL, TSV, and STIX artifacts
│   ├── diagnostics/        # Run report, JSON diagnostics, and auto summary
│   └── changelog/          # Markdown changelog between runs
├── scripts/                # Utility helpers for post-processing
│   └── summarize_iocs.py   # Generates Markdown summaries for Pages & artifacts
├── tests/                  # Offline pytest suite (parsers, STIX, dedup)
├── requirements.txt        # Python runtime dependencies
├── requirements-dev.txt    # Runtime + lint/type/test tooling
├── pyproject.toml          # Ruff, Pyright, and pytest configuration
├── sources.example.yml     # Sample feed configuration
├── swiftioc.py             # Main collector implementation & CLI
├── index.html              # Optional GitHub Pages entry point
├── README.md               # This document
└── SECURITY.md             # Security reporting policy
```

> **Note on outputs & git:** the compact `latest.csv` and `latest.jsonl` feeds
> are committed to the repository, while the bulkier regenerated formats
> (`latest.json`, `latest.tsv`, `stix2.json`) are ignored by git and instead
> published through GitHub Pages and workflow artifacts. This keeps the
> repository small while still exposing every format at the published site.

## 🧠 How it works
1. **Load configuration** – `swiftioc.py` reads `sources.yml` (falling back to
   `sources.example.yml` when needed) and sets up logging, user agents, and
   output directories. 
2. **Collect per source** – each API or RSS source is routed to a parser
   registered via `@register_parser`, which fetches and converts raw feed data
   into `Indicator` objects. Sources are fetched concurrently.
3. **Deduplicate & filter** – indicators are normalised, merged, deduplicated,
   filtered for false positives, and bounded by the configured lookback window.
4. **Score & age** – each indicator receives a 0–100 score; with
   `--persist-feed` the previous feed is merged in and stale entries expire.
5. **Publish outputs** – all formats, diagnostics, and changelog entries are
   written beneath the chosen output directory. 

## 📈 Indicator scoring & the living feed
Every published indicator carries a `score` (0–100) computed as:

```
score = (confidence base + corroboration bonus) × 0.5^(age / half-life)
```

- **Confidence base** – `high` = 80, `medium` = 60, `low` = 40 (assigned by the
  source adapter).
- **Corroboration bonus** – +8 per additional independent source reporting the
  same indicator, capped at +16. An IP flagged by Feodo Tracker *and* ThreatFox
  *and* a vendor blog outranks a single scanner hit.
- **Age decay** – exponential on hours since `last_seen`, with per-type
  half-lives that mirror how quickly each indicator class goes stale: URLs and
  IPs decay in about a week (phishing pages die fast; C2 IPs get reassigned),
  domains in two, curated CIDR blocks and JA3 fingerprints in a month, file
  hashes over six months, and CVEs over a year.

With `--persist-feed` (enabled in the scheduled collection workflow) the
previous `latest.jsonl` is merged into each run, making the published feed
**stateful**: re-observed indicators refresh to full score with their original
`first_seen` and accumulated source history preserved, indicators that stop
appearing decay run over run, and anything whose score falls below
`--min-score` (default 20) is expired from the feed. The same score is emitted
as the STIX 2.1 `confidence` property, so downstream platforms can prioritise
on it directly.

## 🏁 Quick start
Prerequisites:
- Python 3.10 or newer (tested with CPython on Linux and GitHub Actions)
- `pip` for dependency management

```bash
# 1. Clone and enter the repository
git clone https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector.git
cd SwiftIOC-Automated-Threat-Intelligence-Collector

# 2. (Optional) Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows PowerShell

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the collector with the sample sources
python -m swiftioc --sources sources.example.yml --out-dir public
```

Artifacts appear under `public/`. Add `--verbose` for progress logging or
`--self-test` to run the built-in sanity checks without touching the network.


## 🧾 Configuring sources
Create a `sources.yml` to describe the feeds you care about. The file mirrors the
structure in `sources.example.yml` and supports per-source options. `window_hours`
defines the global lookback window; override it for individual feeds using
`--source-window name=HOURS` on the CLI. 

```yaml
window_hours: 48

apis:
  - name: cisa_kev
    kind: json
    parse: kev
    url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

  - name: urlhaus_recent_urls
    kind: csv
    parse: urlhaus
    url: https://urlhaus.abuse.ch/downloads/csv_recent/
    reference: https://urlhaus.abuse.ch/
    # Optional filter supplied via --urlhaus-status

rss:
  - name: google_tag
    url: https://blog.google/threat-analysis-group/rss/
    reference: https://blog.google/threat-analysis-group/
```

Each parser can accept additional keyword arguments defined under `options:`.
Custom parsers are supported via Python dotted paths (for example,
`parse: my_package.parsers:parse_feed`).

For feeds without a dedicated adapter you can fall back to the universal
collector by setting `parse: universal`. It will autodetect JSON, CSV, or plain
text payloads, discover common timestamp/tag fields, and extract indicators via
the same heuristics used for RSS content.

## 📋 CLI reference
Run `python -m swiftioc --help` for the full list of switches. Highlights:

| Flag | Purpose |
| --- | --- |
| `--out-dir PATH` | Directory where artifacts are written (`public/` by default). |
| `--sources PATH` | YAML configuration (`sources.yml`, falls back to `sources.example.yml`). |
| `--window-hours N` | Global lookback window in hours. |
| `--skip-rss` | Disable RSS processing entirely. |
| `--max-per-source N` | Cap the number of indicators taken from each source. |
| `--max-workers N` | Number of sources fetched concurrently (default `8`; use `1` to disable threading). |
| `--no-fp-filter` | Disable bogon / false-positive filtering (keep private IPs, `example.com`, etc.). |
| `--persist-feed` | Living feed: merge the previously published `latest.jsonl`, decay scores by age, expire stale entries. |
| `--min-score N` | Expire indicators whose decayed score falls below `N` (default `20`). |
| `--high-confidence-score N` | Score at/above which an indicator enters the curated `high_confidence` feed (default `80`; multi-source indicators always qualify). |
| `--urlhaus-status {any,online,offline}` | Filter URLhaus indicators by status. |
| `--source-window name=N` | Override the lookback window for specific sources. |
| `--grace-on-404 name…` | Treat HTTP 404 for listed sources as a non-fatal empty result. |
| `--fail-on-empty name…` | Fail the run if any listed sources return zero indicators. |
| `--fail-if-stale name=N` | Fail when the newest indicator from `name` is older than `N` hours. |
| `--save-raw-dir PATH` | Persist raw feed responses for later inspection. |
| `--diag-json PATH` | Write diagnostics JSON (defaults to `<out-dir>/diagnostics/run.json`). |
| `--report PATH` | Write Markdown run report (defaults to `<out-dir>/diagnostics/REPORT.md`). |
| `--ua-file PATH` | Provide a custom user-agent pool (one UA per line). |
| `--ci-safe` | Convenience flag for CI runs (JSON logs, ensures diagnostics dirs, tolerates missing RSS dependency). |
| `--self-test` | Execute built-in assertions without fetching feeds. |
| `-v/--verbose` | Increase console logging (`-vv` for debug). |
| `--log-file PATH` | Send logs to a file. |
| `--log-format {text,json}` | Choose console/file log format. |
| `--log-file-level LEVEL` | Control the file log level (default `DEBUG`). |

## 📦 Outputs & diagnostics
The collector populates the following structure (paths relative to `--out-dir`):

```
public/
├── index.md
├── iocs/
│   ├── latest.csv
│   ├── latest.tsv
│   ├── latest.json
│   ├── latest.jsonl
│   ├── high_confidence.csv    # curated: score ≥80 or 2+ sources
│   ├── high_confidence.jsonl  # same, machine-readable
│   └── stix2.json
├── changelog/
│   └── CHANGELOG.md
└── diagnostics/
    ├── REPORT.md
    ├── run.json
    ├── summary.md
    └── raw/                 # present when --save-raw-dir is used
```

The diagnostics include per-source counts, duplicate statistics, earliest and
latest timestamps, and any recorded failures. These summaries are useful for CI
status checks and dashboards.

## 🌍 GitHub Pages preview & publishing
SwiftIOC ships with a Pages-ready dashboard so the collected indicators can be
browsed without additional tooling. The project uses `public/` as both the
artifact directory and the published site root:

- `public/index.html` renders the live preview, source breakdowns, tag counts,
  and export links using the JSON/JSONL outputs produced by `swiftioc.py`.
- `index.html` at the repository root provides a branded landing page that
  redirects to `public/` after a short delay while offering quick links for
  manual navigation.

To publish on GitHub Pages:

1. Run the collector locally or in CI to populate `public/` (see
   [Quick start](#-quick-start)).
2. Commit the generated artifacts or upload them as a workflow artifact (as
   shown in [Running in GitHub Actions](#-running-in-github-actions)).
3. Enable GitHub Pages with the **GitHub Actions** source so deployments pick up
   the latest `public/` output automatically.

The dashboard ranks preview rows by the collector's 0–100 relevance score
(corroboration + freshness baked in), then by how many independent sources
confirm each indicator, so the most dangerous and most corroborated IOCs sit at
the top of the feed. A "Show" filter isolates high-score (≥80), corroborated
(2+ sources), or new (last 48h) indicators, and multi-source rows carry a
`×N confirmed` badge. Mobile breakpoints convert the preview table into
card-style rows for a phone-friendly experience, and all metadata is defanged
to stay safe for casual browsing.

## ⚙️ Running in GitHub Actions
SwiftIOC runs cleanly inside GitHub Actions and emits artifacts that can be
published via GitHub Pages. The workflow below collects IOCs hourly and deploys
`public/`:

```yaml
name: SwiftIOC – Threat Intel Collector

on:
  schedule:
    - cron: "0 * * * *"   # Run every hour
  workflow_dispatch:       # Allow manual runs from the Actions tab

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: "pages"
  cancel-in-progress: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Collect recent IOCs
        run: python -m swiftioc --ci-safe --window-hours 48 --out-dir public

      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: ./public

  deploy:
    environment:
      name: github-pages
    runs-on: ubuntu-latest
    needs: build
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```

`--ci-safe` enables JSON logging, ensures diagnostic directories exist, and
suppresses hard failures when the optional RSS dependency is missing.


## 🧪 Auto-generated IOC summary
The helper script [`scripts/summarize_iocs.py`](scripts/summarize_iocs.py)
turns the diagnostics and JSONL output into Markdown summaries. It runs
automatically in the "Collect – SwiftIOC" workflow and can also be executed
manually:

```bash
python scripts/summarize_iocs.py \
  --diag public/diagnostics/run.json \
  --ioc-jsonl public/iocs/latest.jsonl
```

Override `--out` or `--index` to control where the summary is written. When the
repository is published with GitHub Pages, everything under `public/` becomes the
site content.

## 🧑‍💻 Development & testing
Contributions are welcome. Set up a development environment and run the same
checks CI runs:

```bash
pip install -r requirements-dev.txt

ruff check .          # lint
pyright               # static type check
python swiftioc.py --self-test   # built-in sanity assertions
pytest -q             # offline unit tests (parsers, STIX, dedup, changelog)
```

The `tests/` suite is fully offline—parsers that would hit the network have
their HTTP layer monkeypatched—so it is safe to run anywhere and catches feed
format drift before it reaches production. When `stix2` is installed the suite
also validates the generated bundle against the reference library.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a new feed parser and the
full contribution workflow.

---

For security disclosures, please see [SECURITY.md](SECURITY.md).
