# ⚡ SwiftIOC – Automated Threat Intelligence Collector (Python + GitHub Actions)

SwiftIOC is a **lightweight, zero-infrastructure threat intelligence collector** that automatically fetches the latest **Indicators of Compromise (IOCs)** from trusted open-source feeds like **CISA KEV**, **URLhaus**, and **MalwareBazaar**.

Built entirely with **Python** and **GitHub Actions**, it runs on a simple schedule—no servers, databases, or manual updates required.  
SwiftIOC normalizes, deduplicates, and enriches threat data, then publishes clean, ready-to-use feeds in **CSV**, **JSON**, and **STIX 2.1** formats—perfect for integration with **Splunk**, **Cortex XDR**, **MISP**, or **OpenCTI**.

> 🧠 Ideal for SOC analysts, threat hunters, detection engineers, and cybersecurity researchers who want **fresh threat intel** without maintaining heavy infrastructure.

## 🔍 Key Features

- 🕒 **Recent-Only Collection** — gathers IOCs from the last 24–48 hours for timely visibility  
- 🔌 **Feed-Driven Architecture** — customize or extend sources via a simple `sources.yml` file  
- 🧹 **Normalized Output** — standard fields for IPs, domains, URLs, hashes, and CVEs  
- 🧠 **Enrichment Ready** — supports optional lookups using AbuseIPDB, URLhaus, ASN, and GeoIP  
- 📦 **Zero-Infrastructure Setup** — runs fully on GitHub Actions, no server or database required  
- 📄 **Open Formats** — exports CSV, JSON, and STIX 2.1 for SIEM and threat-intel platforms  
- 📊 **Seamless Integration** — feed files can be imported into Splunk, Cortex XDR, MISP, or OpenCTI  
- 🧩 **Defanged Indicators** — safely share URLs and IPs without risk of accidental execution  
- 🧠 **Ideal for** SOC teams, CTI analysts, blue teams, and security researchers

## 🗂️ Output Structure

When SwiftIOC runs (locally or through GitHub Actions), it automatically generates a clean set of IOC artifacts inside the `public/` directory.

public/
├── iocs/
│ ├── latest.csv
│ ├── latest.json
│ └── stix2.json
└── changelog/
└── CHANGELOG.md

Each run updates:
- **`iocs/`** — machine-readable IOC files ready for import into SIEM or threat-intel tools  
- **`changelog/`** — markdown summary of what changed since the last update (useful for analysts)

Every IOC entry follows a normalized schema:

| Field | Description |
|--------|-------------|
| `indicator` | IOC value (IP, domain, URL, hash, CVE) |
| `type` | Indicator type (ipv4, domain, url, sha256, etc.) |
| `source` | Feed or source name |
| `first_seen` / `last_seen` | ISO 8601 timestamps for time of observation |
| `confidence` | low / medium / high |
| `tlp` | Traffic Light Protocol label (default: CLEAR) |
| `tags` | Related threat or malware family tags |
| `reference` | Link to original report or feed |
| `context` | Short free-text context or description |

> 📄 Outputs are **defanged by default** to ensure safety when shared or published.

## 🚀 Quick Start

You can run SwiftIOC locally for testing or let **GitHub Actions** run it automatically on a schedule.

### 🧩 Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/swift-ioc.git
cd swift-ioc

# 2. (Optional) Create and activate a virtual environment
python -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the collector manually
python -m swiftioc --out-dir public
```

## ⚙️ GitHub Actions Automation

SwiftIOC is designed to run entirely through **GitHub Actions** — no servers, cron jobs, or databases required.

By default, it can execute hourly to pull new IOCs, normalize them, and publish updated feeds directly to your repository’s `public/` folder.

### 🕐 Example Workflow (`.github/workflows/pages.yml`)

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
        run: python -m swiftioc --window-hours 48 --out-dir public

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
