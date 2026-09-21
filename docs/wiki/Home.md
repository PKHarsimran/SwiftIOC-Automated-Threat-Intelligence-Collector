# SwiftIOC field guide

**From a public threat report to an explainable analyst decision.**

SwiftIOC combines a Python threat-intelligence collector with a static browser dashboard. It turns different public feeds into consistent, attributed records, maintains a bounded living snapshot, and helps analysts investigate observables and prioritize vulnerability evidence.

[Open the dashboard](https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/) · [Browse the code](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector) · [Prepare for an interview](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide)

[![Collection status](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/collect.yml/badge.svg?branch=main)](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/collect.yml)
[![CI status](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/actions/workflows/ci.yml)
[![Retained snapshot](https://img.shields.io/endpoint?url=https%3A%2F%2Fharsim.ca%2FSwiftIOC-Automated-Threat-Intelligence-Collector%2Fbadge.json&label=Snapshot&cacheSeconds=3600)](https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/diagnostics/run.json)

Badges describe the published snapshot and workflow status, not complete upstream coverage or guaranteed freshness. Check their linked timestamps and diagnostics.

![Five-stage pipeline: collect, normalize, validate, maintain, publish.](https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/76421f9f4d7a5e007ec2990debf715cd3eefebe3/docs/wiki/assets/pipeline.png)

<details>
<summary>Play the animated pipeline walkthrough</summary>

![Animated walkthrough highlighting collection, normalization, quality validation, persistence and publication in sequence.](https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/76421f9f4d7a5e007ec2990debf715cd3eefebe3/docs/wiki/assets/pipeline.gif)

The same explanation is available as the static diagram above and in [Architecture](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Architecture). Animation is optional; no step relies on motion alone.

</details>

## Choose your path

| You are here to… | Read in this order |
| --- | --- |
| Understand the project in five minutes | [Overview](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Project-Overview) → [Architecture](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Architecture) |
| Investigate threat intelligence | [Analyst walkthrough](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Analyst-Workflow) → [Graph and discovery](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Graph-and-Discovery) → [SPL and integrations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/SPL-and-Integrations) |
| Prioritize vulnerabilities | [CVE and exposure guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/CVE-and-Exposure) |
| Run your own collector | [Installation](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Installation) → [Sources](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Sources-and-Parsers) → [Operations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Operations-and-Troubleshooting) |
| Explain the engineering in an interview | [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) → [Data and scoring](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Data-and-Scoring) → [Security](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Security-and-Privacy) |
| Extend the project | [Development](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Development-and-Testing) → [Roadmap](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Roadmap-and-Tradeoffs) |

## The complete handbook

1. [Project overview](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Project-Overview): problem, audience, capabilities, boundaries.
2. [Installation](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Installation): macOS, Linux, Windows, Docker, first run.
3. [Architecture](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Architecture): code map, pipeline, trust boundaries, failure paths.
4. [Sources and parsers](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Sources-and-Parsers): configuration, collection, extension points.
5. [Data and scoring](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Data-and-Scoring): identity, timestamps, decay, retention, Delta.
6. [Analyst workflow](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Analyst-Workflow): investigation from lookup to saved evidence.
7. [CVE and exposure](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/CVE-and-Exposure): exploitation, watches, inventory, uncertainty.
8. [Graph and discovery](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Graph-and-Discovery): relationships, provider aliases, bounded views.
9. [SPL and integrations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/SPL-and-Integrations): hunts, snapshots, Delta consumers, signatures.
10. [Detection packs](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Detection-Packs): Sigma, Suricata, RPZ, stable identifiers, verification.
11. [Operations and troubleshooting](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Operations-and-Troubleshooting): scheduling, quality gates, recovery.
12. [Security and privacy](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Security-and-Privacy): publication filtering, credentials, browser state.
13. [Development and testing](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Development-and-Testing): checks, fixtures, frontend maintenance.
14. [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide): pitches, demo script, design questions, bug-fix stories.
15. [Roadmap and tradeoffs](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Roadmap-and-Tradeoffs): credible next steps and how to measure them.
16. [Reference and glossary](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary): CLI, outputs, terminology, documentation upkeep.

**Start with one distinction:** an IOC is a value to investigate in telemetry; a CVE identifies a vulnerability. Neither a feed match nor a high score is proof that your system is compromised.

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
