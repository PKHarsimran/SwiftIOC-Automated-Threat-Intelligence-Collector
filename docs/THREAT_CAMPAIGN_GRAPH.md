# Threat Campaign Graph

The Threat Campaign Graph turns the compact dashboard feed into a browser-local relationship map. It helps an analyst move from a flat IOC list to useful pivots without asserting attribution that the underlying evidence cannot support.

## Relationship model

The graph creates two kinds of pivot:

- **Tag pivots** connect indicators that share a malware family, behavior, campaign, or other source-supplied tag.
- **Source pivots** connect indicators reported by the same intelligence provider.

Generic severity and feed-management tags are excluded, as are tags that duplicate a source name. Singleton pivots are omitted because they do not express a relationship. Remaining pivots are ranked by membership, IOC score, and corroboration, then bounded to six pivots and 24 indicators so rendering remains predictable on a phone or workstation.

These links are investigative hints. A shared tag or source is not proof that two indicators belong to the same campaign or threat actor, and the dashboard states that limitation beside the graph.

## Analyst interaction

Analysts can switch between combined, tag-only, and source-only views; remix the deterministic radial layout; inspect nodes with a mouse or keyboard; and add an indicator directly to the private investigation queue. The graph rebuilds when the live-preview filters or feed data change, and it never uploads selections or graph state.

Node selection highlights only direct neighbors and fades unrelated paths. This makes dense constellations readable without discarding the wider context. The layout uses an SVG view box and responsive inspector so it remains usable across desktop and mobile widths.

## Safety and performance

- Graph construction accepts only bounded arrays and clips pivot labels.
- Duplicate indicator identities collapse through the same case-aware key used by the investigation workspace.
- Rendering is capped at 30 total nodes by default.
- Motion uses opacity and stroke animation and respects `prefers-reduced-motion`.
- Keyboard users can focus each node and select it with Enter or Space.
