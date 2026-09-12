# 🔐 Security Policy

We take the security of SwiftIOC seriously and appreciate responsible
vulnerability reports. SwiftIOC powers automated threat intelligence workflows,
so timely disclosure helps the cybersecurity community keep pace with adversary
infrastructure. This document explains which versions receive security updates
and how to disclose potential issues.

## ✅ Supported Versions
Security fixes are applied to the latest commit on the `main` branch. Releases
or tags may be created from time to time, but older snapshots are not actively
maintained.

| Version / Branch | Supported |
| ---------------- | --------- |
| `main`           | ✅ |
| anything else    | ❌ |

If you are using a fork or pinned commit, please pull the latest changes from
`main` before reporting an issue to ensure the vulnerability still exists.

## 📣 Reporting a Vulnerability
Please report vulnerabilities **privately** — do not open a public issue or pull
request that describes the problem.

- **Preferred:** use GitHub's
  [private vulnerability reporting](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/security/advisories/new)
  (Security → *Report a vulnerability*). This keeps the details confidential
  until a fix is available.
- Include: affected version/commit, a description of the impact, and clear steps
  to reproduce (a minimal `sources.yml` and command line where relevant).

We aim to acknowledge reports within **5 business days** and to provide a
remediation timeline after triage. Coordinated disclosure is appreciated: please
give us a reasonable window to ship a fix before any public write-up.

## Collected credentials and secret-scanning alerts

Phishing feeds can include third-party credentials inside indicator URLs.
Treat these as exposed data; their presence does not prove that SwiftIOC uses
the credential or owns the associated account. Do not test a collected key
against its provider or paste it into issues, PRs, or test fixtures.

The collector omits records containing recognizable Google API-key values
before persistence and public export, including metadata and nested CVE
evidence. It also filters the previous snapshot before generating Delta, so
removed-record payloads cannot republish the key. It omits the entire record
instead of altering a URL into an unobserved indicator or widening it into a
domain block. Diagnostics report `sensitive_rows_omitted` and
`sensitive_previous_rows_omitted`; source fetch counts still describe ingestion.
This is a targeted pattern safeguard, not comprehensive credential detection.
Standalone writer APIs do not apply it; callers must filter their inputs.

The collection workflow stores raw upstream responses outside `public/` and
excludes legacy raw-capture paths from uploaded artifacts. When running locally,
keep `--save-raw-dir` outside your published directory; raw captures are not
sanitized. In particular, override the raw path when using `--ci-safe`.

Removing a key from current exports does not revoke it or erase historical
commits, old artifacts, forks, or clones. Confirm ownership before resolving an
alert. For a key you control, rotate/revoke it in the provider console and review
usage before marking it revoked. For confirmed third-party threat data, record
that provenance and inability to revoke it; do not claim revocation or label a
potentially real credential as a test key. See
[GitHub's alert-resolution guidance](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-secret-scanning-alerts/resolving-alerts).

Thank you for helping us keep SwiftIOC secure! 🛡️
