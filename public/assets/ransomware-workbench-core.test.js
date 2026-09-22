const test = require('node:test');
const assert = require('node:assert/strict');
const groupCore = require('./group-intel-core.js');
const dashboard = require('./dashboard-core.js');
const core = require('./ransomware-workbench-core.js');

const fixture = () => groupCore.build({ schema_version: 1, generated_at: '2026-09-22T00:00:00Z',
  groups: [{ name: 'A', ttps: ['T1486', 'T1490'] }, { name: 'B', ttps: ['T1486'] }, { name: 'C', ttps: [] }],
  cves: [{ cve_id: 'CVE-2025-1234', groups: ['A', 'B'], in_swiftioc: true }],
  iocs: [{ type: 'domain', indicator: 'bad.example', groups: ['A', 'B'], in_swiftioc: false }, { type: 'ipv4', indicator: '192.0.2.4', groups: ['C'], in_swiftioc: true }],
  evidence_history: { events: [{ group: 'A', kind: 'iocs', type: 'domain', value: 'bad.example', action: 'added', at: '2026-09-21T00:00:00Z' }], observations: {} } });

test('priority is explainable and never exceeds 100', () => {
  const model = fixture(); const cve = model.records.find((r) => r.kind === 'cves');
  const result = core.priority(cve, model, Date.parse('2026-09-22T00:00:00Z'));
  assert.equal(result.score, 65); assert.ok(result.reasons.length >= 3);
});

test('quality measures traceability rather than truth or attribution', () => {
  const model = fixture(); const cve = model.records.find((r) => r.kind === 'cves'); const result = core.quality(cve, model);
  assert.equal(result.score, 80); assert.match(result.meaning, /not truth|not.*truth/i);
});

test('similarity preserves evidence categories and does not imply attribution', () => {
  const result = core.similarities(fixture(), 'A');
  assert.equal(result[0].group, 'B'); assert.deepEqual(result[0].shared, { ttps: 1, cves: 1, iocs: 1 });
});

test('coverage distinguishes mapped gaps from unmapped techniques', () => {
  const result = core.coverage(fixture(), 'A', ['endpoint']);
  assert.ok(result.every((item) => item.status === 'searchable'));
  assert.equal(core.coverage(fixture(), 'A', [])[0].status, 'gap');
});

test('triage and exposure use exact evidence rather than substring guesses', () => {
  const model = fixture();
  assert.equal(core.triage(model, 'bad.example').kind, 'evidence');
  assert.equal(core.triage(model, 'bad'), null);
  assert.deepEqual(core.exposure(model, 'CVE-2025-1234, unknown').unknown, ['unknown']);
});

test('response packs include reviewed multi-format drafts without automatic blocking', () => {
  const pack = core.responsePack(fixture(), 'A', '*', '-7d', dashboard);
  assert.match(pack.ioc_hunts[0].spl, /index=\*/); assert.match(pack.ioc_hunts[0].kql, /bad\.example/);
  assert.equal(pack.ioc_hunts[0].sigma.status, 'experimental'); assert.equal(pack.review.automatic_blocking, false);
  assert.match(pack.suricata_rules, /dns\.query/); assert.match(pack.sigma_rules, /status: experimental/);
});

test('watchlist data stays structured and matches only requested values', () => {
  const result = core.watchMatches(fixture(), { activity: { countries: [{ name: 'US', count: 2 }], sectors: [{ name: 'Health', count: 1 }] } },
    { groups: 'A', evidence: '192.0.2.4', countries: 'US', sectors: 'Health' });
  assert.equal(result.groups[0], 'A'); assert.equal(result.evidence[0].value, '192.0.2.4'); assert.equal(result.countries[0].count, 2);
});
