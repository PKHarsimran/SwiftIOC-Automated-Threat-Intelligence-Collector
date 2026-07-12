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

Thank you for helping us keep SwiftIOC secure! 🛡️
