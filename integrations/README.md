# SOC integration starters

SwiftIOC publishes a full snapshot and a small change stream. Poll
`public/iocs/delta.jsonl` every four hours for routine automation and use
`latest.jsonl` for initial synchronization or recovery.

## Generic pipeline

```bash
curl --fail --silent --show-error \
  https://harsim.ca/SwiftIOC-Automated-Threat-Intelligence-Collector/iocs/delta.jsonl \
  | jq -c 'select(.action == "added" or .action == "updated") | .current'
```

Treat `removed_from_feed` as a request to remove the IOC from the SwiftIOC
working set. It is not evidence that the indicator became benign.

## Splunk

Use a scheduled scripted input or HTTP Event Collector forwarder. Set the
event sourcetype to `_json`, use `action` as the change field, and deduplicate
on `current.type + current.indicator` (falling back to `previous` for removals).

## Elastic Security

Send `added` and `updated` event `current` objects to a dedicated indicator
index. Use an ingest pipeline to map `indicator`, `type`, `score`, `source`,
and `tags`; delete the matching document for `removed_from_feed` events.

## Microsoft Sentinel

Use a scheduled Logic App or Function to fetch the JSONL stream, retain
`added` and `updated` events above the local score threshold, and submit them
through the workspace ingestion path. Keep the event `observed_at` as the
checkpoint so retries remain idempotent.

## Verification

When the signing workflow is enabled, each canonical feed has a matching
bundle under `public/signatures/`. Verify before ingestion with:

```bash
cosign verify-blob public/iocs/delta.jsonl \
  --bundle public/signatures/delta.jsonl.sigstore.json \
  --certificate-identity-regexp 'https://github.com/PKHarsimran/SwiftIOC-Automated-Threat-Intelligence-Collector/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```


## DNS response policy export

The generated `detections/dns/swiftioc.rpz` contains exact-domain and wildcard
QNAME triggers. Load it under your chosen response-policy zone origin. Trigger
owners are deliberately relative (`evil.example` and `*.evil.example`); adding
a trailing dot would place them outside that policy zone. The CNAME target `.`
is absolute and specifies the NXDOMAIN action.

Validate the generated file with `named-checkzone YOUR_POLICY_ZONE swiftioc.rpz`
before deployment. See the [BIND RPZ documentation](https://bind9.readthedocs.io/en/v9.16.43/reference.html)
for resolver configuration and policy behavior. Regenerate older SwiftIOC packs
to obtain the corrected relative trigger names.
