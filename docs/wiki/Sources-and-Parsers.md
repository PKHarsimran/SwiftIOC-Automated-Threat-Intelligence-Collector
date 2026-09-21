# Configure and extend collection

`sources.yml` defines API/text sources and optional RSS inputs. The CLI falls back to `sources.example.yml` if the configured file is missing. The global lookback is the CLI's `--window-hours` (48 hours by default); the example YAML's top-level `window_hours` does not override it.

```yaml
apis:
  - name: cisa_kev
    kind: json
    parse: kev
    url: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

  - name: nist_nvd_recent
    kind: json
    parse: nvd
    url: https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=200
    reference: https://nvd.nist.gov/
    options:
      api_key_env: NVD_API_KEY
```

`name` is the stable source identifier used in provenance and source-specific CLI rules. `parse` selects an adapter. `reference` points analysts back to supporting evidence. `options` passes adapter-specific settings. The optional NVD setting reads an environment variable; do not commit the actual key.

## Sources have different meanings

| Family | Typical evidence | Interpretation |
| --- | --- | --- |
| CISA KEV | Known exploitation, vendor/product, required action and dates | Exploitation evidence, not proof an individual asset is affected. |
| NVD | CVE metadata, severity and applicability configurations | Severity/applicability context, not exploitation proof. |
| abuse.ch feeds | URLs, hashes, infrastructure, fingerprints | Multiple exports can share one reporting provider. |
| OpenPhish | Reported phishing URLs | Preserve URL path/query identity; inspect provenance. |
| Spamhaus, DShield, blocklists | Addresses or network ranges | Understand each list's collection and inclusion policy. |
| Tor exits / aggregate feeds | Context or aggregated reporting | Membership does not alone establish malicious behavior or independence. |

Adapters also cover blocklist.de, GreenSnow, CINS Army, Emerging Threats, Binary Defense and IPsum. Availability and authentication requirements depend on the provider. Configuration is not proof of successful ingestion; consult source diagnostics.

## Collection behavior

The default maximum is eight concurrent source fetches; `--max-workers 1` disables threading. Use `--source-window name=HOURS` to override one adapter's lookback and `--max-per-source N` to bound source output. Some feeds are full catalogs or lists; a lookback is only meaningful where their adapter can apply it.

HTTP handling retries selected transient failures, applies a response-size cap and validates redirect targets. NVD pagination preserves already-fetched pages if a later page fails. That avoids discarding usable records, but partial progress must not be mistaken for complete coverage.

## Add an adapter

1. Define a parser registered with `@register_parser("your_name")` in `swiftioc/parsers.py`, accepting `(url, ref_url, source, ws)` plus options and returning `list[Indicator]`.
2. Classify and normalize values through shared helpers; use the existing defanging conventions.
3. Preserve upstream timestamp meaning and evidence. Avoid inventing product/version certainty.
4. Add a source entry and an offline test using a small synthetic payload and a mocked HTTP call.
5. Cover malformed/empty inputs, timestamp boundaries, duplicate values and pagination if relevant.
6. Check source counts and output identity through an end-to-end fixture.

`parse: universal` handles supported JSON, CSV and text feeds without a dedicated adapter. A trusted local extension can use `parse: my_package.parsers:parse_feed`. This imports Python code, so source configurations and installed parser packages are trusted inputs, not untrusted user uploads.

**References:** [example configuration](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/sources.example.yml), [parsers](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/swiftioc/parsers.py), [contributing guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/blob/2725dbf95fe719b45e6d4e2d50d1952b2b34784f/CONTRIBUTING.md).

---
[Wiki home](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki) · [Interview guide](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Interview-Guide) · [Documentation map](https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/wiki/Reference-and-Glossary)

*Reviewed against main at `2725dbf9` on 21 September 2026. Live feed counts change between collections.*
