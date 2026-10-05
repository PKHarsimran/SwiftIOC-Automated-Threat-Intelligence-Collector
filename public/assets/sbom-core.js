(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SwiftIOCSbom = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, () => {
  'use strict';
  const MAX_COMPONENTS = 200;
  const clean = (value) => typeof value === 'string' ? value.trim() : '';
  const validPurl = (value) => /^pkg:[a-z0-9.+-]+\/[^\s?#]{1,300}(?:\?[^\s#]{1,200})?(?:#[^\s]{1,150})?$/i.test(value);
  function parse(input) {
    if (!input || typeof input !== 'object') throw new Error('SBOM must be a JSON object.');
    let raw;
    if (input.bomFormat === 'CycloneDX' && Array.isArray(input.components)) raw = input.components.map((component) => ({
      name: clean(component?.name), version: clean(component?.version), purl: clean(component?.purl),
    }));
    else if (typeof input.spdxVersion === 'string' && input.spdxVersion.startsWith('SPDX-') && Array.isArray(input.packages)) raw = input.packages.map((component) => ({
      name: clean(component?.name), version: clean(component?.versionInfo),
      purl: clean(component?.externalRefs?.find((entry) => /purl/i.test(entry.referenceType || ''))?.referenceLocator),
    }));
    else throw new Error('Use CycloneDX JSON with components or SPDX JSON with packages.');
    if (!raw.length || raw.length > MAX_COMPONENTS) throw new Error(`SBOM must have 1–${MAX_COMPONENTS} components; split larger files.`);
    const seen = new Set(), components = []; let skipped = 0;
    for (const component of raw) {
      const purl = component.purl;
      if (!validPurl(purl) || component.name.length > 160 || component.version.length > 160) { skipped++; continue; }
      const path = purl.split(/[?#]/, 1)[0];
      const versionInPurl = path.lastIndexOf('@') > path.lastIndexOf('/');
      if (!versionInPurl && !component.version) { skipped++; continue; }
      if (versionInPurl && component.version) {
        let purlVersion;
        try { purlVersion = decodeURIComponent(path.slice(path.lastIndexOf('@') + 1)); }
        catch (_) { skipped++; continue; }
        if (purlVersion !== component.version) { skipped++; continue; }
      }
      const query = versionInPurl ? { package: { purl } } : { package: { purl }, version: component.version };
      const key = JSON.stringify(query);
      if (seen.has(key)) continue;
      seen.add(key); components.push({ ...component, query });
    }
    if (!components.length) throw new Error('No components had a valid package URL and version. Product names alone are not enough.');
    return { components, skipped, total: raw.length };
  }
  function combine(components, results) {
    if (!Array.isArray(results) || results.length !== components.length) throw new Error('OSV result count did not match the request.');
    return components.map((component, index) => ({ name: component.name || component.purl, version: component.version,
      purl: component.purl, vulnerabilities: Array.isArray(results[index]?.vulns)
        ? results[index].vulns.filter((row) => /^[-A-Za-z0-9_.]+$/.test(row?.id || '')).map((row) => row.id).slice(0, 100) : [],
      incomplete: Boolean(results[index]?.next_page_token) }));
  }
  return { parse, combine, MAX_COMPONENTS };
});
