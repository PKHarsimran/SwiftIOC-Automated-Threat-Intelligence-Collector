const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('./inventory-core.js');
const asset = { id: 'edge', vendor: 'Vendor', product: 'Server', version: '2.4', cpe_vendor: 'vendor', cpe_product: 'server', exposure: 'internet', importance: 'critical' };
const fixture = (range = {}) => ({ cve_id: 'CVE-2026-1234', exploitation_status: 'known_exploited', reports: {
  cisa_kev: { vendor: 'Vendor', product: 'Server' }, nvd: { configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [
    { vulnerable: true, criteria: 'cpe:2.3:a:vendor:server:*:*:*:*:*:*:*:*', ...range },
  ] }] }] },
} });
const match = (item, overrides = {}) => core.buildReport([{ ...asset, ...overrides }], [item], '2026-09-01').findings[0];
test('inventory rejects malformed, ambiguous and oversized inputs', () => {
  assert.equal(core.parseInventory({ schema_version: 1, assets: [asset] }).length, 1);
  for (const assets of [[asset, asset], [{ ...asset, version: 2 }], [{ ...asset, cpe_product: '' }], [{ ...asset, exposure: 'public' }], Array(201).fill(asset)]) {
    assert.throws(() => core.parseInventory({ schema_version: 1, assets }));
  }
});
test('numeric versions compare components, not lexical strings', () => {
  assert.equal(core.compareVersions('2.10', '2.9'), 1);
  assert.equal(core.compareVersions('2.4.0', '2.4'), 0);
  assert.equal(core.compareVersions('1.0-rc1', '1.0'), null);
  assert.equal(core.compareVersions('999999999999999999999', '2'), 1);
});
test('inclusive and exclusive boundaries are respected', () => {
  assert.equal(match(fixture({ versionStartIncluding: '2.4', versionEndExcluding: '3' })).status, 'version-match');
  assert.equal(match(fixture({ versionStartExcluding: '2.4' })).status, 'outside-reported-range');
  assert.equal(match(fixture({ versionEndIncluding: '2.4' })).status, 'version-match');
  assert.equal(match(fixture({ versionEndExcluding: '2.4' })).status, 'outside-reported-range');
});
test('missing versions and complex or unsupported applicability stay uncertain', () => {
  assert.equal(match(fixture()).status, 'needs-verification');
  assert.equal(match(fixture({ versionEndIncluding: '3' }), { version: '' }).status, 'needs-verification');
  assert.equal(match(fixture({ versionEndIncluding: '3-rc1' })).status, 'needs-verification');
  const item = fixture({ versionEndIncluding: '3' }); item.reports.nvd.configurations[0].operator = 'AND';
  assert.equal(match(item).status, 'needs-verification');
  item.reports.nvd.configurations[0].operator = 'OR'; item.reports.nvd.configurations[0].negate = true;
  assert.equal(match(item).status, 'needs-verification');
});
test('CISA-only product matches never imply version exposure and unmatched assets stay explicit', () => {
  assert.equal(match(fixture(), { cpe_vendor: '', cpe_product: '' }).status, 'needs-verification');
  const report = core.buildReport([{ ...asset, vendor: 'Different', cpe_vendor: 'different' }], [fixture()], '2026-09-01');
  assert.equal(report.findings.length, 0); assert.equal(report.unmatched_assets.length, 1);
});
test('rejected CVEs remain review findings even when versions match', () => {
  const item = fixture({ versionEndIncluding: '3' }); item.reports.nvd.status = 'Rejected';
  assert.equal(match(item).status, 'needs-verification');
});
test('exploit evidence and asset context determine ordering without suppressing outside-range evidence', () => {
  const item = fixture({ versionEndIncluding: '3' });
  const report = core.buildReport([{ ...asset, id: 'internal', exposure: 'internal' }, asset, { ...asset, id: 'patched', version: '4' }], [item], '2026-09-01');
  assert.deepEqual(report.findings.map((row) => row.asset.id), ['edge', 'internal', 'patched']);
});

test('exact versions, platform qualifiers and CPE parts remain distinct', () => {
  const item = fixture();
  const rule = item.reports.nvd.configurations[0].nodes[0].cpeMatch[0];
  rule.criteria = 'cpe:2.3:a:vendor:server:2.4:*:*:*:*:*:*:*';
  assert.equal(match(item).status, 'version-match');
  assert.equal(match(item, { version: '2.5' }).status, 'outside-reported-range');
  rule.criteria = 'cpe:2.3:a:vendor:server:2.4:*:*:*:*:windows:*:*';
  assert.equal(match(item).status, 'needs-verification');
  rule.criteria = 'cpe:2.3:o:vendor:server:2.4:*:*:*:*:*:*:*';
  assert.equal(match(item).status, 'needs-verification');
  assert.equal(match(item, { cpe_part: 'o' }).status, 'version-match');
});

test('separate OR ranges retain a matching version and do not mutate evidence', () => {
  const item = fixture({ versionEndExcluding: '2' });
  const rules = item.reports.nvd.configurations[0].nodes[0].cpeMatch;
  rules.push({ ...rules[0], versionEndExcluding: '3' });
  const before = JSON.stringify(item);
  assert.equal(match(item).status, 'version-match');
  assert.equal(JSON.stringify(item), before);
});
