const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('./group-intel-core.js');

const fixture = () => ({ schema_version: 1, generated_at: '2026-09-22T00:00:00Z',
  groups: [{ name: 'A', ttps: ['T1486'] }, { name: 'B', ttps: ['T1486', 'T1059.001'] }, { name: 'C', ttps: [] }],
  cves: [{ cve_id: 'CVE-2025-1234', groups: ['A', 'B'], in_swiftioc: true }],
  iocs: [{ type: 'url', indicator: 'https://example.org/Case', groups: ['A', 'C'], in_swiftioc: false }],
});
test('group graph uses direct reported links and keeps IOC, CVE and technique evidence distinct', () => {
  const model = core.build(fixture());
  assert.deepEqual(core.graph(model, 'A', 'cves').related, ['B']);
  assert.deepEqual(core.graph(model, 'A', 'iocs').related, ['C']);
  assert.deepEqual(core.graph(model, 'A', 'ttps').related, ['B']);
  assert.equal(core.filter(model, { group: 'C', kind: 'ttps' }).length, 0);
  assert.equal(core.filter(model, { kind: 'iocs', coverage: 'matched' }).length, 0);
});
test('exact lookup associations preserve URL path case', () => {
  const model = core.build(fixture());
  assert.ok(model.byIdentity.has('url:https://example.org/Case'));
  assert.equal(model.byIdentity.has('url:https://example.org/case'), false);
});
test('map caps clutter, reports totals, and includes an explicitly selected record beyond the initial sample', () => {
  const data = fixture();
  for (let i = 0; i < 20; i++) data.cves.push({ cve_id: `CVE-2025-${3000 + i}`, groups: ['A', 'B'], in_swiftioc: false });
  const model = core.build(data);
  const selected = model.records.find((r) => r.value === 'CVE-2025-3019');
  const graph = core.graph(model, 'A', 'cves', selected.key);
  assert.equal(graph.evidence.length, 12);
  assert.equal(graph.total, 21);
  assert.equal(graph.selected.value, selected.value);
  assert.ok(graph.evidence.includes(selected));
});
test('unknown groups and empty evidence do not invent connections', () => {
  const graph = core.graph(core.build(fixture()), 'missing', 'cves');
  assert.equal(graph.total, 0);
  assert.equal(graph.selected, null);
  assert.deepEqual(graph.related, []);
});
