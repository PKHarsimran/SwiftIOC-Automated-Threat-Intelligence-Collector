# ⚡ SwiftIOC – Open Source Automated Threat Intelligence Collector

SwiftIOC is an open-source Python threat intelligence automation toolkit that
keeps recent Indicators of Compromise (IOCs) in machine-readable formats. The
lightweight collector package (`swiftioc`) ingests threat feeds via YAML
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
- [Branch strategy for the packaged edition](#-branch-strategy-for-the-packaged-edition)
- [Features](#-features)
- [Supported threat intelligence sources](#-supported-threat-intelligence-sources)
- [Use cases & SEO-friendly keywords](#-use-cases--seo-friendly-keywords)
- [Repository layout](#-repository-layout)
- [How it works](#-how-it-works)
- [Quick start](#-quick-start)
- [Configuring sources](#-configuring-sources)
- [CLI reference](#-cli-reference)
- [Outputs & diagnostics](#-outputs--diagnostics)
- [Running in GitHub Actions](#-running-in-github-actions)
- [Auto-generated IOC summary](#auto-generated-ioc-summary)

## 🔍 SwiftIOC at a glance
SwiftIOC helps cybersecurity teams automate the collection and publication of
high-fidelity IOCs from authoritative sources. The project emphasises:

- **Automated threat feed aggregation** with YAML-based configuration.
- **Consistent IOC enrichment** ready for SIEM, SOAR, IDS, and DFIR tooling.
- **Git-friendly artefacts** tailored for GitHub Pages, GitHub Actions, and
  other CI/CD environments.

## 🌳 Branch strategy for the packaged edition

This branch (`work`) carries the installable, multi-team edition of SwiftIOC.
It keeps the existing collector logic compatible with the historical repository
while adding packaging metadata, a richer README, and CI expectations suited to
large security programmes. Keeping these changes on a dedicated branch avoids
disrupting the lighter-weight default experience on `main`.

- **GitHub Actions coverage.** The CI workflow now targets both `main` and this
  branch, so pull requests and pushes to `work` receive the same linting,
  testing, and CLI self-checks as the default branch.
- **Scheduled runs.** GitHub only executes scheduled workflows from the default
  branch. When operating exclusively from `work`, trigger collections with the
  provided `workflow_dispatch` inputs or mirror the workflow into your own
  repository where the branch is default.
- **Packaging parity.** Tags created from this branch can be published to a
  private package index without affecting the lightweight clone-and-run users on
  `main`.

## 🪄 Using this branch as a separate product

If you want to treat the packaged edition as its own project—without merging it
back to `main`—work directly from the `work` branch and make it the default in
your fork or downstream repository.

1. **Create a fork or new repository.** Fork this repo on GitHub or create an
   empty repo under your organisation and add it as a new remote.
2. **Push the `work` branch.**

   ```bash
   git clone https://github.com/<your-account>/SwiftIOC-Automated-Threat-Intelligence-Collector.git
   cd SwiftIOC-Automated-Threat-Intelligence-Collector
   git checkout work
   git remote add packaged git@github.com:<your-account>/<new-repo>.git
   git push packaged work:main   # or work:work if you want to keep the name
   ```

   Setting the branch name to `main` in the target repo lets GitHub schedule
   workflows automatically. If you prefer to keep the name `work`, make that the
   default branch in repository settings so the cron-based workflow runs.
3. **Enable GitHub Actions & Pages.** Actions are disabled by default in new
   forks. Turn them on (Settings → Actions → General) and optionally enable
   GitHub Pages to publish the generated dashboard from `public/`.
4. **Update secrets and ownership.** Replace any automation-specific secrets,
   tokens, or email addresses (for example, the auto-commit identity) so the new
   repository reflects your organisation.
5. **Iterate independently.** Continue committing against your packaged branch;
   the CI workflow will exercise the installable package, and the collector
   workflow can be launched manually or on a schedule from your fork.

These steps keep the packaged edition isolated while still benefiting from the
automated tests, dashboards, and documentation tailored to larger teams.

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
  values. 
- **Multiple export formats** – each run emits CSV, TSV, JSON, JSON Lines, a
  STIX 2.1 bundle, and a Markdown changelog. 
- **Rich diagnostics** – a JSON run summary, Markdown report, and per-source
  counts are generated automatically for audits and dashboards. 
- **Optional RSS collection** – RSS feeds are processed when `feedparser` is
  installed; use `--skip-rss` (or `--ci-safe`) to run without the dependency.
- **CI-friendly defaults** – JSON logging, deterministic output paths, and
  guard-rail flags (`--fail-on-empty`, `--fail-if-stale`, `--grace-on-404`) make
  the collector predictable in automation. 

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
├── swiftioc/               # Installable package with collector logic & CLI
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── core.py
├── tests/                  # Pytest-based regression tests
│   └── test_core.py
├── pyproject.toml          # Packaging metadata (install via pip)
├── requirements.txt        # Python dependencies for manual installs
├── sources.example.yml     # Sample feed configuration
├── index.html              # Optional GitHub Pages entry point
├── README.md               # This document
└── SECURITY.md             # Security reporting policy
```

## 🧠 How it works
1. **Load configuration** – the `swiftioc` CLI reads `sources.yml` (falling back to
   `sources.example.yml` when needed) and sets up logging, user agents, and
   output directories. 
2. **Collect per source** – each API or RSS source is routed to a parser
   registered via `@register_parser`, which fetches and converts raw feed data
   into `Indicator` objects. 
3. **Deduplicate & filter** – indicators are merged, deduplicated, and filtered
   by the configured lookback window. 
4. **Publish outputs** – all formats, diagnostics, and changelog entries are
   written beneath the chosen output directory. 

## 🏁 Quick start
Prerequisites:
- Python 3.10 or newer (tested with CPython on Linux and GitHub Actions)
- `pip` for dependency management

```bash
# 1. Clone and enter the repository
git clone https://github.com/<your-username>/SwiftIOC-Automated-Threat-Intelligence-Collector.git
cd SwiftIOC-Automated-Threat-Intelligence-Collector

# 2. (Optional) Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows PowerShell

# 3. Install dependencies (package or requirements file)
pip install .            # installs the swiftioc package and console script
# For local development with linting/type-checking tools, use:
# pip install ".[dev]"
# or, if you prefer the legacy requirements file
# pip install -r requirements.txt

# 4. Run the collector with the sample sources
python -m swiftioc --sources sources.example.yml --out-dir public
# or invoke the console script once installed:
# swiftioc --sources sources.example.yml --out-dir public
```

Artifacts appear under `public/`. Add `--verbose` for progress logging or
`--self-test` to run the built-in sanity checks without touching the network.

## 👥 Deploying SwiftIOC across teams

The installable package lets security, DFIR, and platform engineering teams share
the same collector without cloning this repository. Publish the project to an
internal package index or distribute a signed wheel, then manage
`sources.yml` per environment (production SOC, lab, red team, etc.). Because the
CLI accepts dotted-path parser names, organisations can ship proprietary parser
plugins as separate wheels and list them alongside the built-ins in YAML.

To keep environments consistent:

- Use `pip install .` (or `pip install swiftioc` once published) inside virtual
  environments or automation containers.
- Commit curated `sources.yml` files for each environment and refer to them via
  `--sources path/to/team-sources.yml`.
- Enable the optional `dev` extra (`pip install "swiftioc[dev]"`) on developer
  workstations to gain the same linting, typing, and auditing checks that run in
  CI.
- Reuse the provided GitHub Actions as templates for Jenkins, GitLab CI, or
  other orchestrators—the CLI is self-contained and only depends on the YAML
  configuration.


## 🧪 Running the test suite

The project now ships with lightweight regression tests to keep the core logic
stable. After installing the optional development dependencies, execute:

```bash
pip install ".[dev]"
pytest
```

Tests cover indicator classification, defanging, and deduplication/merging
behaviour for custom parser plugins. They are safe to run offline and require no
network connectivity.


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
| `--urlhaus-status {any,online,offline}` | Filter URLhaus indicators by status. |
| `--source-window name=N` | Override the lookback window for specific sources. |
| `--grace-on-404 name…` | Treat HTTP 404 for listed sources as a non-fatal empty result. |
| `--fail-on-empty name…` | Fail the run if any listed sources return zero indicators. |
| `--fail-if-stale name=N` | Fail when the newest indicator from `name` is older than `N` hours. |
| `--save-raw-dir PATH` | Persist raw feed responses for later inspection. |
| `--diag-json PATH` | Write diagnostics JSON (defaults to `public/diagnostics/run.json`). |
| `--report PATH` | Write Markdown run report (defaults to `public/diagnostics/REPORT.md`). |
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
├── index.html             # Live dashboard powered by summary.json
├── iocs/
│   ├── latest.csv
│   ├── latest.tsv
│   ├── latest.json
│   ├── latest.jsonl
│   └── stix2.json
├── changelog/
│   └── CHANGELOG.md
└── diagnostics/
    ├── REPORT.md
    ├── run.json
    ├── summary.json         # machine-readable highlights for dashboards
    ├── summary.md
    └── raw/                 # present when --save-raw-dir is used
```

The diagnostics include per-source counts, duplicate statistics, earliest and
latest timestamps, and any recorded failures. These summaries are useful for CI
status checks and dashboards. The new `summary.json` powers the enhanced landing
page (`index.html`), which fetches metrics client-side so viewers immediately
see the health of the latest run without waiting for a redirect.

## ⚙️ Running in GitHub Actions
SwiftIOC runs cleanly inside GitHub Actions and emits artifacts that can be
published via GitHub Pages. This repository includes:

- **`CI – SwiftIOC`** for linting, typing, tests, dependency audits, and a
  diagnostic dry run using the new package entry point.
- **`Collect – SwiftIOC`** for scheduled feed aggregation with optional
  GitHub Pages deployment.
- **`Maintenance – SwiftIOC`** for alerting when collections stay empty or
  artifacts go stale.

The snippet below shows a minimal workflow teams can copy into other repos. It
collects IOCs hourly and deploys `public/` as a GitHub Pages site:

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

      - name: Install SwiftIOC package
        run: |
          python -m pip install --upgrade pip
          pip install .

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

---

For security disclosures, please see [SECURITY.md](SECURITY.md).
