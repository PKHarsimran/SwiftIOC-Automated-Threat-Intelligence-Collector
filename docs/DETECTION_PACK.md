# Detection Pack Compiler

SwiftIOC turns its curated high-confidence feed into detection-as-code artifacts on every collection run. This gives analysts a reviewable path from intelligence to telemetry without copying thousands of indicators into hand-written rules.

## Published artifacts

| Artifact | Best for | Behavior |
| --- | --- | --- |
| `detections/sigma/network-iocs.yml` | SIEM and EDR network telemetry | Matches exact IP endpoints and uses Sigma's `cidr` modifier for network ranges. |
| `detections/sigma/dns-iocs.yml` | Normalized DNS telemetry | Matches an exact domain or a label-boundary subdomain suffix. |
| `detections/suricata/swiftioc.rules` | IDS/IPS alerting | Emits inbound, outbound, and DNS alerts with deterministic, collision-checked local SIDs. |
| `detections/dns/swiftioc.rpz` | BIND-compatible DNS policy | Returns NXDOMAIN for exact malicious domains and their subdomains. |
| `detections/manifest.json` | Automation and audit | Reports included types, skipped types, rule counts, generation time, and the review-required policy. |

The compiler accepts IP addresses, IPv4/IPv6 networks, and domains. It records unsupported types such as CVEs, file hashes, email addresses, and URLs in the manifest instead of forcing them into telemetry where they cannot match correctly. Inputs are refanged, validated, normalized, and deduplicated before rule generation.

## Analyst workspace

The live dashboard can compile a smaller case-specific Sigma or Suricata bundle. Add indicators to the private investigation queue and choose **Build Sigma** or **Build Suricata**. Compilation happens entirely in the browser; the selection never leaves the workstation.

Browser exports apply the same type allowlist and reject malformed values before constructing rule text. This prevents modified browser storage from injecting arbitrary Suricata options or YAML fields.

## Operational workflow

1. Download the artifact and its manifest from the live dashboard.
2. Review skipped types and apply local allowlists, asset context, and severity policy.
3. Compile Sigma for the target backend or load the Suricata/RPZ artifact into a staging policy.
4. Run in alert-only mode and measure false positives.
5. Promote through the organization's normal detection change process.

Generated rules intentionally use an alert or experimental status. SwiftIOC supplies evidence and portable detection logic; each environment owns its field mappings, network variables, exceptions, and enforcement decision.
