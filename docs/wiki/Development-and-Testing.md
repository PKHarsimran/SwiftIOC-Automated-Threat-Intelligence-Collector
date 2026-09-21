# Develop with evidence

Install runtime dependencies through the [installation guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Installation), then install development tools:

```bash
python -m pip install -r requirements-dev.txt
ruff check .
pyright
python -m swiftioc --self-test
pytest -q
node --test public/assets/dashboard-core.test.js public/assets/inventory-core.test.js
```

Python 3.10+ is the project target. Frontend tests require Node.js. On Windows, use the corresponding executables under `.venv\Scripts\` if the environment is not activated.

## What each check proves

| Check | Useful evidence | Limit |
| --- | --- | --- |
| Ruff | Selected syntax/import/correctness lint rules. | Not full behavioral verification. |
| Pyright | Static consistency under the project's basic configuration. | Annotations do not validate untrusted JSON at runtime. |
| Self-test | Built-in offline sanity assertions. | Not feed availability or freshness. |
| Pytest | Mocked parser, model, publication, detection and regression behavior. | Fixtures cannot prove every upstream response works. |
| Node core tests | Data logic without a browser. | Not layout, focus or real DOM behavior. |
| Browser suites | User flows, refresh failures, storage and responsive layout with fixtures. | Not a production performance SLA. |
| CI dependency audit / CodeQL | Known dependency issues and static security analysis. | Not a complete penetration test. |

The CI workflow also uses a scoped live-feed smoke run. A small graceful-failure source configuration reduces transient upstream noise; a passing smoke run does not establish full production feed health. Browser suites are documented separately and are not automatically all run by the current CI workflow.

## Browser checks

```bash
npm install --no-save --package-lock=false playwright
npx playwright install chromium
python -m http.server 8765 --directory public
```

In a second terminal:

```bash
node scripts/test_vulnerability_ui.cjs
node scripts/test_dashboard_layout.cjs
node scripts/test_personal_briefing.cjs
node scripts/test_inventory_ui.cjs
node scripts/test_investigation_spl.cjs
node scripts/test_investigation_import.cjs
```

Use `BASE_URL` for another local server and `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` for an existing Chromium executable. Fixtures keep tests repeatable without depending on live threat data.

## Changes worth regression coverage

- Valid first load followed by failed refresh: stale exports and selections must be disabled.
- URL paths differing only in case: both must survive identity and queue operations.
- Carried-forward decay: current rescoring must not mutate the previous baseline.
- Truncated snapshot: no first-run alert flood.
- Exact CPE versions versus numeric ranges: preserve uncertainty and literal identity.
- Large mostly-unmatched inventory: avoid repeated full configuration traversal.
- Cross-origin redirects: parser credentials must not follow the redirect.
- Rejected quality run: preserve published outputs and diagnostics baseline.
- SID disappearance/reappearance: preserve historical collision reservations.

## Frontend maintenance

Keep pure transformations in core modules and DOM behavior in UI modules. Validate imported data rather than relying on types or trusted storage. Exercise keyboard focus, narrow widths, long indicators, empty/error states and reduced motion. When HTML adds controls used by JavaScript, update the related HTML/script/style cache keys together so returning visitors do not receive incompatible mixed versions.

## Documentation and generated pages

Edit SPL sources and `scripts/build_splunk_guide.py`, then regenerate with `python scripts/build_splunk_guide.py`. Text output uses UTF-8. Keep Wiki source copies under `docs/wiki/` and publish their changes to GitHub Wiki separately; a repository PR does not automatically update the Wiki repository.

See [CONTRIBUTING.md](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/CONTRIBUTING.md), [CI](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/.github/workflows/ci.yml) and [reference upkeep](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary).

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
