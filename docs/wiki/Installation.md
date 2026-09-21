# Run SwiftIOC yourself

To browse intelligence, [open the hosted dashboard](https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/). Installation is needed to collect your own snapshot or develop the project.

## macOS and Linux

Requires Git and Python 3.10 or newer.

```bash
git clone https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector.git
cd SwiftIOC-Automated-Threat-Intelligence-Collector
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp sources.example.yml sources.yml
python -m swiftioc --self-test
python -m swiftioc --sources sources.yml --out-dir public --persist-feed --max-age-days 30 --max-store 10000
python -m http.server 8765 --directory public
```

Open [localhost:8765](http://localhost:8765). The collection command makes network requests; the self-test does not. Stop the local web server with Ctrl+C.

## Windows PowerShell

Using the virtual environment's executable directly avoids requiring an activation-policy change.

```powershell
git clone https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector.git
Set-Location SwiftIOC-Automated-Threat-Intelligence-Collector
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
Copy-Item sources.example.yml sources.yml
.\.venv\Scripts\python.exe -m swiftioc --self-test
.\.venv\Scripts\python.exe -m swiftioc --sources sources.yml --out-dir public --persist-feed --max-age-days 30 --max-store 10000
.\.venv\Scripts\python.exe -m http.server 8765 --directory public
```

## Docker

The image runs the collector as a non-root user. Use a named volume to retain snapshots between runs:

```bash
docker build -t swiftioc .
docker volume create swiftioc-data
docker run --rm -v swiftioc-data:/data swiftioc
```

The default container command enables persistence, 30-day age retention and a 10,000-record cap. It writes data to `/data`; it does not run a dashboard web server or scheduler. The image does not include the frontend `public/` tree. For a hosted dashboard, combine generated data with the repository's frontend files and serve them over HTTP. With bind mounts, ensure UID 10001 can write the destination. The Docker health check is a self-test, not a live feed freshness check.

## Confirm the first run

1. Check `public/diagnostics/run.json` and `REPORT.md` for source counts and errors.
2. Confirm `public/iocs/latest.jsonl` exists and contains the expected retained data.
3. Confirm generated `public/collections/` files exist; some generated formats are ignored by Git and may be absent in a fresh checkout.
4. Open the dashboard through HTTP, not by double-clicking `index.html`.
5. Check the snapshot timestamp in the UI. A page loading successfully does not establish a successful recent collection.

A partial collection can succeed when sources fail unless you configure quality gates. Read [Operations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Operations-and-Troubleshooting) before scheduling unattended runs.

## Keep local output separate when experimenting

`--out-dir` selects the output destination; it does not copy frontend HTML/assets there. For parser experiments, use a separate output directory. To browse that output, explicitly place it alongside a copy of the frontend. Preserve `latest.jsonl` and its corresponding diagnostics together if you need a usable Delta baseline.

**Implementation:** [package metadata](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/pyproject.toml), [Dockerfile](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/Dockerfile), [CLI](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/swiftioc/cli.py).

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
