# ⚡ SwiftIOC – Open-Source Automated Threat Intelligence Collector

SwiftIOC is an **open-source, zero-infrastructure threat intelligence collector**
that automatically aggregates the latest Indicators of Compromise (IOCs) from
trusted cybersecurity feeds. It transforms the raw data into machine-readable,
defanged formats that are ideal for **security operations centers (SOC), threat
hunting teams, incident responders, and detection engineers** who need timely
intel without the overhead of maintaining custom pipelines.

The project ships as a single Python module (`swiftioc.py`) and runs anywhere
Python 3.11+ is available—including **GitHub Actions**, CI/CD pipelines, or a
lightweight workstation. By default SwiftIOC focuses on **fresh activity from
the last 24–48 hours**, normalizes and deduplicates IOCs, and publishes feeds
ready for SIEM, SOAR, EDR, and threat intelligence platforms.

> 🧠 Use SwiftIOC to keep pace with malware campaigns, phishing URLs, botnet
> infrastructure, ransomware hashes, and CVEs circulating across the security
> community—without building your own aggregator.

## 📚 Table of Contents
- [Key capabilities](#-key-capabilities-for-cybersecurity-automation)
- [Use cases & benefits](#-use-cases--benefits)
- [Repository layout](#-repository-layout)
- [How the collector works](#-how-the-collector-works)
- [Getting started locally](#-getting-started-locally)
- [Running in GitHub Actions](#-running-in-github-actions)
- [Configuring sources](#-configuring-sources)
- [CLI reference](#-cli-reference)
- [Outputs & diagnostics](#-outputs--diagnostics)
- [Integrations & compatibility](#-integrations--compatibility)
- [Roadmap & contributing](#-roadmap--contributing)

## 🚀 Key capabilities for cybersecurity automation
- 🕒 **Recent-only lookback** – configurable collection window (48h default)
  ensures feeds stay focused on active adversary infrastructure.
- 🔌 **Feed-driven architecture** – add or disable feeds via YAML without touching
  code, making it simple to align with your threat intelligence requirements.
- 🧹 **Normalization & defanging** – IP addresses, URLs, domains, file hashes,
  CVEs, and malware families are typed, deduplicated, and safely defanged for
  sharing across security tooling.
- 📄 **Multiple export formats** – export to CSV, TSV, JSON, JSON Lines, and
  STIX 2.1 for immediate ingestion by SIEM, SOAR, EDR, TIP, and DFIR workflows.
- 📊 **Actionable reporting** – detailed run diagnostics, per-source statistics,
  and change summaries power dashboards and automated quality checks.
- 🧠 **Enrichment hooks** – AbuseIPDB, URLhaus, ASN lookups, GeoIP context, and
  parser enrichments are built in and toggled through the source definitions.
- 🧩 **CI friendly** – deterministic CLI flags, optional raw feed capture, and
  guardrails that prevent CI runs from silently succeeding on empty feeds.
- 🌐 **GitHub Pages ready** – outputs publish directly to `public/` so you can
  host a live threat intelligence portal in minutes.

## 🎯 Use cases & benefits
- **SOC automation** – push vetted IOCs into detection content or blocklists on
  a predictable schedule.
- **Threat hunting** – triage fresh indicators, enrich with context, and pivot
  quickly using defanged URLs and MITRE ATT&CK-aligned tagging.
- **Incident response** – compare live incident data against curated feeds to
  confirm or disprove compromise quickly.
- **Security research** – monitor vendor advisories and malware trackers to
  inform blog posts, newsletters, and situational awareness briefings.

SwiftIOC helps teams reduce manual feed collection, stay aligned with the MITRE
ATT&CK® framework, and ensure downstream tools receive consistent IOC data.

## 🗂️ Repository layout
```
├── public/                 # Default output directory for generated feeds
│   ├── iocs/               # CSV, JSON, JSONL, TSV, and STIX artifacts
│   ├── diagnostics/        # Run report, JSON diagnostics, and auto summary
│   └── changelog/          # Markdown changelog between runs
├── scripts/                # Utility helpers for post-processing
│   └── summarize_iocs.py   # Generates Markdown summaries for Pages & artifacts
├── requirements.txt        # Python dependencies
├── sources.example.yml     # Sample feed configuration
├── swiftioc.py             # Main collector implementation & CLI
├── README.md               # This document
└── SECURITY.md             # Security reporting policy
```

## 🧠 How the collector works
1. **Load sources** – `swiftioc.py` reads `sources.yml` (or
   `sources.example.yml`) to discover JSON, CSV, and RSS feeds.
2. **Fetch & parse** – each source is fetched with retrying HTTP clients and a
   rotating User-Agent pool. Feed-specific parsers normalize the data into a
   unified schema.
3. **Normalize** – every indicator is typed, defanged, timestamped, and
   attributed to its originating source.
4. **Deduplicate & filter** – duplicates are removed and the collection window is
   enforced globally or per-source.
5. **Publish** – indicators and run diagnostics are written to the `public/`
   directory, ready to be served via GitHub Pages or consumed by downstream
   systems.

## 🧪 Getting started locally
Prerequisites:
- Python **3.11+**
- A virtual environment is recommended

```bash
# 1. Clone and enter the repository
git clone https://github.com/<your-username>/SwiftIOC-Automated-Threat-Intelligence-Collector.git
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

Artifacts will appear under `public/`. Add `--verbose` to watch progress, or
`--self-test` to run quick assertions verifying the classifier and defanging
helpers.

## ⚙️ Running in GitHub Actions
SwiftIOC ships with a workflow-friendly CLI and writes outputs to `public/`,
which can be published directly via **GitHub Pages** or stored as artifacts.
Below is an example workflow (`.github/workflows/pages.yml`) that executes hourly
and deploys the latest feeds to Pages:

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
suppresses failures when optional dependencies (like `feedparser` for RSS) are
missing.

## 🛠️ Configuring sources
Create a `sources.yml` file to describe the feeds you care about. The
`window_hours` setting defines the default lookback period. Each source entry can
override behaviour (such as per-source window or fallback URLs). A trimmed
example:

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

rss:
  - name: google_tag
    url: https://blog.google/threat-analysis-group/rss/
    reference: https://blog.google/threat-analysis-group/
```

To disable RSS handling (and the `feedparser` dependency), pass `--skip-rss` at
runtime. When a requested `sources.yml` file is missing, the CLI automatically
falls back to `sources.example.yml`.

## 🧾 CLI reference
Run `python -m swiftioc --help` for the full list of switches. Highlights:

| Flag | Purpose |
| --- | --- |
| `--out-dir PATH` | Where to write generated artifacts (`public/` by default). |
| `--sources PATH` | YAML configuration of API and RSS feeds (`sources.yml`). |
| `--window-hours N` | Global lookback window (hours). Override per source via `--source-window name=N`. |
| `--urlhaus-status {any,online,offline}` | Filter URLhaus indicators by status. |
| `--max-per-source N` | Cap the number of indicators recorded from each source. |
| `--fail-on-empty name…` | Fail the run if any listed sources return zero indicators. |
| `--fail-if-stale name=N` | Fail the run if newest indicator from `name` is older than `N` hours. |
| `--save-raw-dir PATH` | Persist the raw feed responses for auditing/debugging. |
| `--diag-json PATH` | Write a structured diagnostics summary (defaults to `public/diagnostics/run.json`). |
| `--report PATH` | Generate a Markdown run report (defaults to `public/diagnostics/REPORT.md`). |
| `--ci-safe` | Convenience flag for CI environments (JSON logs, tolerant RSS handling). |
| `--self-test` | Execute built-in sanity checks instead of collecting feeds. |

## 📦 Outputs & diagnostics
Running the collector produces the following structure (paths relative to
`--out-dir`):

```
public/
├── index.md
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
    ├── summary.md
    └── raw/                 # optional when --save-raw-dir is supplied
```

All indicators share a common schema (`indicator`, `type`, `source`,
`first_seen`, `last_seen`, `confidence`, `tlp`, `tags`, `reference`, `context`).
`REPORT.md` and `run.json` summarise totals, per-source counts, type breakdowns,
and any issues encountered, while `summary.md` condenses the run into a portal-
ready Markdown snapshot that also drives `public/index.md`.

### Auto-generated IOC summary

The helper script [`scripts/summarize_iocs.py`](scripts/summarize_iocs.py)
produces the Markdown summary and GitHub Pages landing page. It runs
automatically in the **Collect – SwiftIOC** workflow and also appends the same
information to the GitHub Actions job summary. You can execute it locally after
any collection run:

```bash
python scripts/summarize_iocs.py \
  --diag public/diagnostics/run.json \
  --ioc-jsonl public/iocs/latest.jsonl
```

Override `--out` or `--index` if you want to write the summary elsewhere.
The workflow ships with GitHub Pages deployment enabled, so everything under
`public/`—including the summary—goes live after each successful run.

**🧭 High-level Data Flow**
flowchart LR
  A[sources.yml<br/>+ CLI flags] --> B[Collector Orchestrator<br/><code>collect_from_yaml()</code>]
  subgraph S[Adapters]
    K[CISA KEV]:::adp
    U[URLhaus CSV]:::adp
    M[MalwareBazaar CSV]:::adp
    T[ThreatFox JSON]:::adp
    F[Feodo IP Blocklist]:::adp
    J[SSLBL JA3/JA3S]:::adp
    H[Spamhaus DROP]:::adp
    O[OpenPhish]:::adp
    C[CINS Army]:::adp
    R[Tor Exit Nodes]:::adp
    RSS[RSS (iocextract)]:::adp
  end
  B --> S
  S --> C1[(Indicator List)]
  C1 --> D[Deduplicate & Merge<br/>(by type+indicator)]
  D --> E[[Writers]]
  E --> E1[CSV/TSV/JSON/JSONL]
  E --> E2[STIX 2.1 Bundle]
  E --> E3[Changelog.md]
  D --> G[Diagnostics<br/>run.json + REPORT.md]
  classDef adp fill:#eef,stroke:#99f;

**🔧 Runtime Architecture**

graph TD
  main --> parse_args[argparse CLI]
  parse_args --> logging[configure_logging()]
  parse_args --> ua[_load_ua_file()]
  parse_args --> cfg[load sources.yml]
  parse_args --> collect[collect_from_yaml()]
  collect --> adapters
  adapters --> indicators[(List[Indicator])]
  indicators --> dedup[dedupe + merge_conf + tag union]
  dedup --> outputs
  outputs --> csv[write_csv/tsv/json/jsonl]
  outputs --> stix[write_stix]
  outputs --> change[write_changelog]
  outputs --> diag[diagnostics json + report]
  main --> summary[append_gh_summary()]


## 🔌 Integrations & compatibility
SwiftIOC plays well with popular security platforms and file formats:

- **SIEM & log platforms:** Splunk, Elastic, Microsoft Sentinel, QRadar, Sumo
  Logic
- **SOAR & automation:** Cortex XSOAR, Tines, Shuffle, Torq
- **Threat intelligence platforms:** MISP, OpenCTI, Anomali, ThreatConnect
- **Blocklists & firewalls:** pfSense, Palo Alto Networks, Fortinet, Cisco

Use the standard export formats or extend the CLI to push to custom REST APIs,
message queues, or data lakes.

## 📈 Roadmap & contributing
Have ideas for new feeds, enrichments, or output formats? We welcome issues and
pull requests. Join the conversation by opening a GitHub issue outlining the
problem, enhancement, or research collaboration you have in mind. For
security-sensitive reports, follow the [security policy](SECURITY.md).

If you build something cool with SwiftIOC, share it! Blog posts, YouTube demos,
and conference talks help other defenders discover the project.
