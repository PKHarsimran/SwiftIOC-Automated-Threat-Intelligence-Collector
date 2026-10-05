# SwiftIOC field guide

**From a public threat report to a reviewable analyst decision.**

SwiftIOC has two halves: a Python collector turns configured feeds into attributed, bounded files; a static website lets people investigate those files. It separates IOC telemetry leads, CVE exploitation evidence, product applicability, and optional ransomware-group reporting instead of treating them as the same claim.

[Open the live dashboard](https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/) · [Read the project README](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector#readme) · [Check collection diagnostics](https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/diagnostics/summary.html)

![Five-stage pipeline: collect, normalize, validate, maintain, publish.](https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/76421f9f4d7a5e007ec2990debf715cd3eefebe3/docs/wiki/assets/pipeline.png)

The diagram is a summary; [How SwiftIOC works](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/How-It-Works) follows a record through each stage and explains where failures, browser state, and optional PRO data fit.

## Pick the route that matches your question

| If you want to… | Read this path |
| --- | --- |
| Understand the whole system | [How it works](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/How-It-Works) → [Architecture](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Architecture) → [Data and scoring](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Data-and-Scoring). |
| Investigate an IOC | [Analyst workflow](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Analyst-Workflow) → [Graph and discovery](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Graph-and-Discovery) → [SPL and integrations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/SPL-and-Integrations). |
| Review vulnerabilities or your assets | [CVE and exposure](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/CVE-and-Exposure) → [Ransomware intelligence](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Ransomware-Intelligence) if group reporting matters. |
| Run your own copy | [Installation](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Installation) → [Sources and parsers](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Sources-and-Parsers) → [Operations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Operations-and-Troubleshooting). |
| Extend or assess the project | [Development and testing](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Development-and-Testing) → [Security and privacy](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Security-and-Privacy) → [Roadmap and tradeoffs](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Roadmap-and-Tradeoffs). |
| Explain the engineering | [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide), with the [reference and glossary](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary) alongside it. |

## A useful mental model

1. **Published evidence is a bounded snapshot.** It reflects configured sources, their successes and failures, lookback, scoring, and retention—not every possible threat or vulnerability.
2. **A browser match is a lead.** The site does not scan your systems or search your SIEM. Queue, watch, and inventory features help you make a local working set and draft a query or review.
3. **Different claims stay separate.** CISA KEV confirms known exploitation of a CVE in general; NVD describes severity and applicability; ransomware.live may report a group association; your own asset and telemetry data establish local relevance.

No match is not proof of safety. A high score is not a compromise probability. Shared reporting is not attribution.

## Other guides

[Detection packs](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Detection-Packs) explains generated Sigma/Suricata/RPZ drafts and verification. [Project overview](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Project-Overview) explains audience and scope. The [reference and glossary](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary) maps outputs and CLI options. The sidebar lists every page.

This wiki is published from reviewable copies in the main repository's [`docs/wiki/`](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/tree/main/docs/wiki). The wiki itself is a separate Git repository, so both copies need updating when behavior changes. Live feed counts and source timestamps belong in [diagnostics](https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/diagnostics/summary.html), not in a static guide.
