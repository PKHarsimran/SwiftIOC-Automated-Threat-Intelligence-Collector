'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('./today-core.js');
const groupCore = require('./group-intel-core.js');
const dashboard = require('./dashboard-core.js');
const now = Date.parse('2026-10-02T12:00:00Z');
const date = '2026-10-02T10:00:00Z';
const items = [
  { cve_id: 'CVE-2026-1000', title: 'Gateway issue', exploitation_status: 'known_exploited', reports: { cisa_kev: { vendor: 'Vendor', product: 'Gateway', required_action: 'Patch' }, nvd: { severity: 'high', configurations: [{}] } } },
  { cve_id: 'CVE-2026-2000', title: 'Other issue', exploitation_status: 'not_established', reports: { cisa_kev: { vendor: 'Vendor', product: 'Other' } } },
  { cve_id: 'CVE-2026-3000', title: 'Rejected', exploitation_status: 'known_exploited', reports: { nvd: { status: 'Rejected' } } },
];
const model = groupCore.build({ schema_version: 1, generated_at: date, groups: [{ name: 'alpha' }, { name: 'beta' }], iocs: [],
  cves: [{ cve_id: items[0].cve_id, groups: ['alpha', 'beta'], in_swiftioc: true }, { cve_id: 'CVE-2026-9000', groups: ['alpha'], in_swiftioc: false }],
  evidence_history: { observations: { first: { kind: 'cves', group: 'alpha', value: items[0].cve_id, present: true, last_observed: date } } } });
test('freshness treats missing, invalid, future and stale timestamps separately', () => {
  for (const value of [undefined, null, 'bad', '2027-01-01', '1960-01-01']) assert.equal(core.freshness(value, now), 'unavailable');
  assert.equal(core.freshness('2026-09-29', now), 'stale');
  assert.equal(core.freshness(date, now), 'current');
});
test('catalog preserves provider records and adds exact unmatched group CVEs', () => {
  const all = core.catalog(items, model);
  assert.equal(all.length, 4);
  assert.equal(all[0], items[0]);
  assert.equal(all[3].cve_id, 'CVE-2026-9000');
  assert.equal(all[3].exploitation_status, 'not_established');
});
test('public CVE signals enrich missing details without turning a forecast into exploitation evidence', () => {
  const signals = { items: { 'CVE-2026-9000': { epss: { probability: .35, percentile: .98 },
    official_cve: { description: 'Official affected-product description', affected: [{ vendor: 'A', product: 'B' }],
      cisa_ssvc: { options: { Exploitation: 'poc' } } } } } };
  const missing = core.catalog(items, model, signals).find((item) => item.cve_id === 'CVE-2026-9000');
  assert.equal(missing.exploitation_status, 'not_established');
  assert.equal(missing.description, 'Official affected-product description');
  const profile = core.evidenceProfile(missing, model, date, now);
  assert.match(profile.claims.find((claim) => claim.source === 'FIRST EPSS').boundary, /not a severity score/);
  assert.match(core.nextStep({ item: missing, findings: [] }), /official CVE/);
});
test('evidence profile separates claims and never promotes feed matches to corroboration', () => {
  const profile = core.evidenceProfile(items[0], model, date, now);
  assert.equal(profile.receipts, 1);
  assert.equal(profile.hasVersionRules, true);
  assert.equal(profile.groups.length, 2);
  assert.match(profile.corroboration, /not established/);
  assert.match(profile.claims[1].boundary, /does not independently confirm/);
  assert.ok(profile.gaps.some((gap) => gap.includes('observation receipt')));
  const missing = core.evidenceProfile(core.catalog(items, model)[3], model, '2026-09-20', now);
  assert.ok(missing.gaps.some((gap) => gap.includes('details are missing')));
  assert.ok(missing.gaps.some((gap) => gap.includes('stale')));
});
test('Today matches exact products, groups and CVEs without broad personal guesses', () => {
  assert.equal(core.recommendations(items, model).personal, false);
  const result = core.recommendations(core.catalog(items, model), model, { watches: [{ vendor: 'vendor', product: 'gateway' }] });
  assert.equal(result.personal, true);
  assert.deepEqual(result.top.map((entry) => entry.item.cve_id), ['CVE-2026-1000']);
  assert.equal(core.recommendations(items, model, { watches: [{ vendor: 'Vendor', product: 'Gate' }] }).top.length, 0);
  assert.equal(core.recommendations(items, model, { groupWatch: { evidence: 'CVE-2026-100' } }).top.length, 0);
  assert.equal(core.recommendations(items, model, { groupWatch: { groups: 'alp' } }).top.length, 0);
  assert.equal(core.recommendations(items, model, { groupWatch: { countries: 'US' } }).personal, false);
  assert.equal(core.recommendations(items, model).ranked.some((r) => r.item.cve_id === 'CVE-2026-3000'), false);
});
test('collection highlights surface recent KEV additions ahead of equally reported older CVEs', () => {
  const older = { ...items[0], cve_id: 'CVE-2020-1000', reports: { cisa_kev: { date_added: '2020-01-01' } } };
  const recent = { ...items[0], cve_id: 'CVE-2026-9999', reports: { cisa_kev: { date_added: '2026-10-01' } } };
  const result = core.recommendations([older, recent], null, {}, now);
  assert.equal(result.top[0].item.cve_id, recent.cve_id);
  assert.ok(result.top[0].reasons.includes('Added to CISA KEV in the last 30 days'));
  assert.ok(!result.top[1].reasons.includes('Added to CISA KEV in the last 30 days'));
});
const report = { snapshot_generated_at: date, truncated: true, findings: [
  { cve_id: 'CVE-2026-1000', status: 'version-match', asset: { id: 'a', exposure: 'internet', importance: 'critical' } },
  { cve_id: 'CVE-2026-1000', status: 'needs-verification', asset: { id: 'b' } },
  { cve_id: 'CVE-2026-1000', status: 'outside-reported-range', asset: { id: 'c' } },
  { cve_id: 'CVE-2026-2000', status: 'needs-verification', asset: { id: 'a' } },
] };
test('Today inventory relevance excludes outside-range findings and prioritizes unreviewed evidence', () => {
  const result = core.recommendations(items, model, { report, reviewed: (item) => item.cve_id === 'CVE-2026-1000' });
  assert.equal(result.top[0].item.cve_id, 'CVE-2026-2000');
  assert.equal(result.ranked.find((entry) => entry.item.cve_id === 'CVE-2026-1000').findings.length, 2);
});
test('patch scenario deduplicates CVEs and distinguishes assets, findings, uncertainty and remaining associations', () => {
  const before = JSON.stringify(report);
  const plan = core.patchPlan(core.catalog(items, model), model, report, ['CVE-2026-1000', 'CVE-2026-1000', 'CVE-2026-8888']);
  assert.equal(plan.selected_cves.length, 1);
  assert.equal(plan.findings_before, 3);
  assert.equal(plan.findings_in_scenario, 2);
  assert.equal(plan.findings_remaining, 1);
  assert.equal(plan.version_rule_matches, 1);
  assert.equal(plan.needs_verification, 1);
  assert.equal(plan.outside_range_excluded, 1);
  assert.deepEqual(plan.asset_ids, ['a', 'b']);
  assert.equal(plan.groups.find((g) => g.group === 'alpha').other_reported_cves, 1);
  assert.equal(plan.inventory_truncated, true);
  assert.equal(JSON.stringify(report), before);
  assert.equal(core.patchPlan(items, null, null, []).inventory_loaded, false);
});
test('Today baselines reject malformed records and fingerprints track real group changes', () => {
  const baseline = { version: 2, snapshotAt: now / 1000, groupAt: now, records: { 'CVE-2026-1000': dashboard.vulnerabilityEvidence(items[0], core.recordFor(model, items[0].cve_id)) } };
  assert.equal(core.validBaseline(baseline), true);
  for (const invalid of [null, {}, { ...baseline, records: [] }, { ...baseline, records: { invalid: {} } }]) assert.equal(Boolean(core.validBaseline(invalid)), false);
  assert.deepEqual(dashboard.vulnerabilityChanges(baseline.records['CVE-2026-1000'], dashboard.vulnerabilityEvidence(items[0], { groups: ['alpha'], matched: true })), ['Group associations changed']);
});
