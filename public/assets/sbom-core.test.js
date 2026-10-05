'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('./sbom-core.js');

test('CycloneDX parsing requires a package URL and exact version', () => {
  const result = core.parse({ bomFormat: 'CycloneDX', components: [
    { name: 'jinja2', version: '3.1.4', purl: 'pkg:pypi/jinja2' },
    { name: 'unnamed', version: '1', purl: '' },
  ] });
  assert.equal(result.components.length, 1);
  assert.equal(result.skipped, 1);
  assert.deepEqual(result.components[0].query, { package: { purl: 'pkg:pypi/jinja2' }, version: '3.1.4' });
});
test('SPDX versioned purl does not duplicate version in OSV query', () => {
  const result = core.parse({ spdxVersion: 'SPDX-2.3', packages: [{ name: 'demo', versionInfo: '1.2.3',
    externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/demo@1.2.3' }] }] });
  assert.deepEqual(result.components[0].query, { package: { purl: 'pkg:npm/demo@1.2.3' } });
});
test('conflicting SBOM and package URL versions are skipped', () => {
  const result = core.parse({ bomFormat: 'CycloneDX', components: [
    { name: 'bad', version: '2.0', purl: 'pkg:pypi/bad@1.0' },
    { name: 'good', version: '1.0', purl: 'pkg:pypi/good@1.0' },
  ] });
  assert.equal(result.skipped, 1);
  assert.equal(result.components.length, 1);
  assert.equal(result.components[0].name, 'good');
});
test('OSV result count is validated and pagination stays visible', () => {
  const components = core.parse({ bomFormat: 'CycloneDX', components: [{ name: 'a', version: '1', purl: 'pkg:pypi/a' }] }).components;
  assert.throws(() => core.combine(components, []), /result count/);
  const rows = core.combine(components, [{ vulns: [{ id: 'CVE-2026-1000' }], next_page_token: 'next' }]);
  assert.deepEqual(rows[0].vulnerabilities, ['CVE-2026-1000']);
  assert.equal(rows[0].incomplete, true);
});
