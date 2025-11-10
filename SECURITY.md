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
1. **Do not create a public issue.** Instead, open a [GitHub Security Advisory
   report](https://github.com/SwiftOnSecurity/SwiftIOC-Automated-Threat-Intelligence-Collector/security/advisories/new)
   or email `security@swiftsecurity.blog`.
2. Include as much detail as possible:
   - Steps to reproduce or proof-of-concept
   - Affected configuration (CLI flags, `sources.yml`, environment)
   - Potential impact or exploitation scenario
3. You will receive an acknowledgement within **3 business days**. We aim to
   provide status updates at least every **7 days** until the report is
   resolved.
4. Once a fix is ready, we will coordinate a disclosure timeline with you. By
   default we release patches publicly as soon as mitigations are available.

Thank you for helping us keep SwiftIOC secure! 🛡️
