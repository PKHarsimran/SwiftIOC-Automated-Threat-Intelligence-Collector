# Your first investigation

Start with a question: “Have we seen this observable?” or “Does this exploited vulnerability apply to our software?” The dashboard provides evidence and working sets; your own telemetry and asset inventory determine the next action.

![Four investigation steps: find, inspect, select, act.](https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/76421f9f4d7a5e007ec2990debf715cd3eefebe3/docs/wiki/assets/investigation.png)

<details>
<summary>Play the investigation walkthrough</summary>

![Animated explanation of finding evidence, inspecting it, selecting a working set and validating an action.](https://raw.githubusercontent.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/76421f9f4d7a5e007ec2990debf715cd3eefebe3/docs/wiki/assets/investigation.gif)

</details>

## Observable investigation

1. **Check freshness.** Look at the published snapshot and source health before treating results as current.
2. **Look up the value.** Ordinary and defanged forms are supported. Preserve the full URL path/query when checking a URL.
3. **Inspect evidence.** Read sources, timestamps, tags, context and score. Check the original report where appropriate; do not navigate directly to a suspicious indicator.
4. **Explore relationships.** Use the graph and discovery desk to form a hypothesis. A shared source or tag is a lead, not attribution.
5. **Build a working set.** Add relevant records to the investigation queue. Row menus keep copy, SPL and other actions compact; adding to the queue remains prominent.
6. **Open Workspace.** Use the persistent shortcut instead of scrolling through the whole page. Keyboard users have an early navigation path too. Back to results returns to the earlier position.
7. **Hunt or export.** Configure the live workspace SPL for your index, time range and field names. Copy/download the query, or export selected evidence in an appropriate format.
8. **Validate in your environment.** Correlate with assets, user activity and expected traffic before escalation or enforcement.

## Resume and recover

The queue holds up to **50 indicators**. Export JSON to keep a portable investigation copy. “Resume a saved investigation” imports up to **500 KB**, merges with the queue, preserves existing evidence for duplicates and rejects invalid/over-capacity input without partially changing the queue.

Undo restores one prior queue change, including ordering and generated SPL. It is held in page memory and disappears on reload. Duplicate-only imports do not consume a meaningful undo step. If saving to browser storage fails, the UI offers a retry; export before leaving.

## What is saved where

| State | Location |
| --- | --- |
| Investigation queue | Browser local storage when available; no account/device synchronization. |
| Undo and workspace SPL configuration | Current page memory. |
| Quick row-SPL index preference | Browser local storage when available. |
| Product watches and review state | Browser local storage when available. |
| Imported asset inventory | Current tab memory; not uploaded or saved to local storage. |

The distinction between quick row-SPL and workspace SPL settings reflects the current implementation. Read [SPL and integrations](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/SPL-and-Integrations) before using either query.

## When the record is a CVE

A CVE-only queue shows a software-verification checklist rather than workspace IOC SPL. Use **Review evidence** to open the exact CVE across statuses, then compare vendor/product/version evidence. Mixed queues generate workspace SPL only for supported observables and disclose exclusions.

## Share evidence, not certainty

Exported files contain the working set you selected. Shared filter links can expose search terms; inspect them before sharing. Clearing browser storage can remove your saved queue/watches. A feed-refresh failure must not leave an enabled export of stale removed rows. If the UI reports unavailable evidence, resolve freshness before relying on a result.

Next: [CVE review](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/CVE-and-Exposure), [graph interpretation](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Graph-and-Discovery), [hunt setup](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/SPL-and-Integrations).

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
