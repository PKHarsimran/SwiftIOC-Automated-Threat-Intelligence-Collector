# Operate a dependable snapshot

The repository collection workflow is scheduled every four hours and supports manual runs. It collects, verifies detection outputs, builds summaries, commits selected outputs and deploys the built public tree. Scheduled jobs can be delayed. Site uptime and data freshness are different signals.

## Deploy your own fork

1. Review `sources.yml`, credentials and provider terms.
2. Enable Actions and set Pages to deploy through Actions.
3. Set the appropriate `--site-url` for generated links; review workflow settings such as `ENABLE_PAGES`.
4. Store provider credentials in secrets/environment variables, not YAML or public artifacts.
5. Run collection manually and inspect diagnostics before relying on the schedule.
6. Confirm the generated CVE/observable collections and detection files are present on the deployed site.

For another scheduler, preserve the output directory between runs and prevent simultaneous writers. Collection and history workflows share a concurrency group because both update main. History builds a compact summary from Git; signing is a separate workflow. See the [workflow directory](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/tree/main/.github/workflows) for current triggers and permissions.

## Quality gates before publication

| Gate | Rejects when… | Caveat |
| --- | --- | --- |
| `--fail-on-empty SOURCE` | A required source returns zero. | Does not establish complete upstream coverage. |
| `--fail-if-stale SOURCE=HOURS` | Newest valid, non-future source `first_seen` is too old. | Measures recent entries, not HTTP availability/poll time; 1–876000 hours. |
| `--fail-if-volume-drop SOURCE=PERCENT` | Count falls by at least the threshold versus the last published positive baseline. | 1–100%; comparable settings required; missing positive baseline is disclosed and skipped. |
| `--warn-if-volume-drop SOURCE=PERCENT` | Configured volume change warrants a warning. | A warning does not prevent publication. |

```bash
python -m swiftioc --sources sources.yml --out-dir public \
  --persist-feed --max-age-days 30 --max-store 10000 \
  --fail-on-empty urlhaus_recent_urls \
  --fail-if-volume-drop urlhaus_recent_urls=50
```

An unknown source in required checks fails. Choose thresholds from observed source behavior; adding arbitrary strict checks can reject valid collections. Freshness timestamps are collected per source before cross-source deduplication, so another provider cannot make a stale source appear fresh.

## Two diagnostic records, two meanings

- `diagnostics/run.json` describes the published run and acts as the next baseline.
- `diagnostics/collection-attempt.json` records quality-check acceptance/rejection, attempted counts, source failures and reasons. “Accepted” means the quality phase passed, not that all later writes or deployment finished.

On quality rejection, the command exits with code 1 without replacing feed exports or their baseline. The attempt report remains available locally/in failed-run artifacts. Individual output files are atomic; the full directory is not transactional. For publication write failures, inspect both process status and output generation consistency.

## Troubleshooting decision table

| Symptom | First checks | Recovery |
| --- | --- | --- |
| Dashboard unavailable locally | HTTP server URL and directory; browser errors. | Serve `public/` over HTTP and generate data. |
| CVEs missing after clone | Generated collections may be ignored by Git. | Run collector; inspect source failures. |
| Source returns zero | HTTP status, authentication, parser format, time window. | Fix cause; rerun with an appropriate window. |
| Lower retained count | Filter omissions, score expiry, age and storage caps. | Separate ingestion count from retained count before adjusting limits. |
| Quality check rejects | Attempt report and previous published counts. | Investigate source/config change; preserve baseline. |
| Delta empty on first run | `baseline_available`. | Expected: establish a baseline without an alert flood. |
| Detection verification fails | Missing files, sizes/hashes, registry state. | Recover a coherent pack and rerun verification. |
| Signature mismatch | Feed and bundle may be from different generations. | Fetch a coherent pair and verify; do not bypass. |
| Queue/review state disappears | Browser storage permission or different profile. | Use exported JSON; retry storage if appropriate. |

## Inspect raw responses privately

Use an explicit private directory only when needed:

```bash
python -m swiftioc --sources sources.yml --out-dir public --save-raw-dir _private/diagnostics/raw
```

Raw responses are not sanitized. `--ci-safe` does not implicitly enable capture. CI and collection keep captures outside the public tree and exclude legacy raw paths from uploaded public artifacts. Public diagnostics can still contain operational source context; review what your custom adapters log.

**Implementation:** [quality checks](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/swiftioc/quality.py), [CLI](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/swiftioc/cli.py), [collection workflow](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/.github/workflows/collect.yml).

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
