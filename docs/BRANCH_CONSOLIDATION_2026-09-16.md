# Branch consolidation audit — 2026-09-16

The audit started from `main` at `eb59ee2600b3fba9722268cd84ca6e54fc06c868`. Six branches existed on GitHub: main, three already-merged fix branches, and two pending dependency branches. Local historical branches were also compared with merged PR heads/trees and subsequent feature work.

## Active GitHub branches

| Branch | Disposition |
| --- | --- |
| `main` | Consolidation target. |
| `fix/collected-key-publication` | Already merged through #117. |
| `fix/publication-quality-gates` | Already merged through #118, including custom diagnostics-path fix. |
| `fix/detection-pack-verification` | Already merged through #119. |
| `dependabot/pip/ruff-gte-0.16.7` | Include Ruff >=0.16.7 from #120. |
| `dependabot/pip/pyright-gte-1.1.414` | Include Pyright >=1.1.414 from #121. |

The dependency branches edit adjacent lines in `requirements-dev.txt`; their merge conflict was resolved by keeping both upgrades. The consolidation commit retains both dependency heads as parents so their history is incorporated, rather than just copying their version strings.

## Historical local branches

Old pre-squash commits need not be ancestors of main to have their changes included. Re-merging their obsolete snapshots could undo later fixes. Branch references and the original working directory are preserved.

| Local branch | Evidence / disposition |
| --- | --- |
| `audit/dependency-pr-validation` | Commit already reachable from main. |
| `audit/reliability-improvements` | Early collector, exports, Delta and workspace iterations superseded by merged PRs #84, #87, #88 and #89 and subsequent fixes. |
| `docs/readme-analyst-guide` | Exact head published through merged PR #115. |
| `docs/readme-onboarding` | Same tree as merged PR #91 despite differing commit metadata. |
| `feat/analyst-investigation-workspace` | Same tree as merged PR #89 despite differing commit metadata. |
| `feat/analyst-next-steps` | Exact head published through merged PR #116. |
| `feat/calm-analyst-interface` | Exact head published through merged PR #99. |
| `feat/campaign-graph-intelligence` | Exact head published through merged PR #94. |
| `feat/cve-priority-views` | Exact head published through merged PR #98. |
| `feat/dashboard-motion-polish` | Exact head published through merged PR #106. |
| `feat/detection-pack` | Pack work merged in #92; later local graph enrichment is superseded by #94 and later graph improvements. |
| `feat/discovery-desk` | Exact head published through merged PR #95. |
| `feat/graph-evidence-explorer` | Exact head published through merged PR #101. |
| `feat/immersive-dashboard` | Merged #90 has the same application code; remaining README differences are superseded by later documentation. |
| `feat/investigation-spl` | Exact head published through merged PR #108. |
| `feat/local-exposure-briefing` | Exact head published through merged PR #103. |
| `feat/personal-cve-briefing` | Exact head published through merged PR #100. |
| `feat/spl-hunt-settings` | Exact head published through merged PR #109. |
| `feat/splunk-hunt-library` | Exact head published through merged PR #104. |
| `feat/technical-motion` | Exact head published through merged PR #107. |
| `feat/threat-visual-motion` | Exact head published through merged PR #111. |
| `feat/undo-investigation` | Exact head published through merged PR #114. |
| `feat/vulnerability-collections` | Exact head published through merged PR #96. |
| `feat/workspace-shortcut` | Exact head published through merged PR #110. |
| `fix/collected-key-publication` | Commit already reachable from main. |
| `fix/detection-pack-verification` | Commit already reachable from main. |
| `fix/discovery-source-aliases` | Exact head published through merged PR #97. |
| `fix/frontend-spacing` | Exact head published through merged PR #113. |
| `fix/graph-search-and-rpz` | Exact head published through merged PR #102. |
| `fix/inventory-product-index` | Inventory code merged in #105; merged branch additionally incorporated later main/Splunk-guide changes. |
| `fix/malwarebazaar-sha256-82` | Exact head published through merged PR #83. |
| `fix/publication-quality-gates` | Commit already reachable from main. |
| `fix/snapshot-row-validation` | Exact head published through merged PR #112. |

## Additional fixes and validation

- CI raw captures now stay under `_private/diagnostics/raw`; the legacy public raw path is explicitly excluded from artifact uploads.
- `--ci-safe` no longer silently enables raw captures under `public/`. Explicit `--save-raw-dir` remains supported and tested.
- A fresh environment with Ruff 0.16.7 and Pyright 1.1.414 passes 224 Python tests, 63 JavaScript tests, lint, self-tests, and type checking with zero errors or warnings.
- Six browser suites pass: workspace import, SPL, dashboard navigation/layout, CVE views, software inventory and personal briefings.
- Runtime dependency audit reports no known vulnerabilities in the resolved dependencies at audit time. This is not a claim that every possible bug or vulnerability is absent.
- CI/collection workflow YAML and raw-artifact exclusions were checked.
