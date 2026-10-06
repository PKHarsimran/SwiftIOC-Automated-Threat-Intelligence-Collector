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

test('coverage summary separates unmatched IOC candidates from CVE retention', () => {
  const summary = core.coverageSummary(fixture());
  assert.equal(summary.candidates, 1);
  assert.equal(summary.feedIocMatches, 1);
  assert.equal(summary.feedCveMatches, 1);
  assert.equal(core.coverageSummary(fixture(), 'C').candidates, 0);
  assert.equal(core.coverageSummary(fixture(), 'C').feedIocMatches, 1);
});

test('candidate review queue hides completed local decisions by default and can reopen them', () => {
  const model = fixture(); const candidate = model.records.find((record) => record.kind === 'iocs' && !record.matched);
  const decisions = { [candidate.key]: { status: 'observed', at: '2026-09-22T00:00:00Z' } };
  assert.equal(core.priorityQueue(model, { decisions }).records.length, 0);
  assert.equal(core.priorityQueue(model, { decisions }).decisionCounts.observed, 1);
  assert.equal(core.priorityQueue(model, { decisions, review: 'observed' }).records[0].key, candidate.key);
  assert.equal(core.priorityQueue(model, { decisions, review: 'all', observable: 'hash' }).records.length, 0);
  assert.equal(core.priorityQueue(model, { group: 'C' }).decisionCounts.pending, 0);
  assert.equal(core.priorityQueue(model, { kind: 'cves', decisions }).records.length, 1);
});

test('stored candidate decisions must have bounded keys, statuses and dates', () => {
  const valid = 'iocs:domain:bad.example';
  assert.deepEqual(core.normalizeDecisions({ [valid]: { status: 'observed', at: '2026-09-22T00:00:00Z' },
    garbage: { status: 'dismissed', at: '2026-09-22T00:00:00Z' },
    'iocs:domain:future.example': { status: 'observed', at: '2027-01-01T00:00:00Z' } }, Date.parse('2026-09-23T00:00:00Z')),
  { [valid]: { status: 'observed', at: '2026-09-22T00:00:00.000Z' } });
});

test('exported evidence case preserves a reviewable snapshot and compares later changes', () => {
  const model = fixture(); const record = model.records.find((row) => row.kind === 'iocs' && !row.matched);
  const saved = core.casePack(model, record, { decision: { status: 'observed', at: '2026-09-22T00:00:00Z' },
    buildSpl: dashboard.buildSplQuery }, Date.parse('2026-09-23T00:00:00Z'));
  assert.equal(saved.record.value, 'bad.example');
  assert.deepEqual(saved.record.groups, ['A', 'B']);
  assert.equal(saved.analyst_decision.status, 'observed');
  assert.match(saved.draft_hunt, /bad\.example/);
  assert.equal(core.compareCase(core.parseCase(saved), model).snapshotSame, true);
  const later = fixture(); later.generatedAt = '2026-09-24T00:00:00Z';
  later.records.find((row) => row.key === record.key).groups = ['B', 'C'];
  assert.deepEqual(core.compareCase(saved, later).addedGroups, ['C']);
  assert.deepEqual(core.compareCase(saved, later).removedGroups, ['A']);
  assert.throws(() => core.parseCase({ ...saved, analyst_decision: { status: 'verified actor' } }), /supported/);
});

test('future provider change cannot boost candidate priority', () => {
  const model = fixture(); const candidate = model.records.find((row) => row.kind === 'iocs' && !row.matched);
  model.history.events[0].at = '2027-01-01T00:00:00Z';
  assert.equal(core.priority(candidate, model, Date.parse('2026-09-22T00:00:00Z')).reasons.some((reason) => reason.includes('last 30 days')), false);
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
