(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.SwiftIOCInventory = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  const text = (value) => typeof value === 'string' ? value.trim() : '';
  const same = (a, b) => text(a).toLowerCase() === text(b).toLowerCase();
  const parseInventory = (value) => {
    if (value?.schema_version !== 1 || !Array.isArray(value.assets) || !value.assets.length || value.assets.length > 200) throw new Error('Use schema_version 1 with 1–200 assets.');
    const ids = new Set();
    return value.assets.map((asset, index) => {
      if (!asset || typeof asset !== 'object') throw new Error(`Asset ${index + 1} must be an object.`);
      const clean = {};
      for (const field of ['id', 'vendor', 'product', 'version', 'cpe_vendor', 'cpe_product']) {
        if (asset[field] != null && typeof asset[field] !== 'string') throw new Error(`Asset ${index + 1}: ${field} must be text.`);
        clean[field] = text(asset[field]);
        if (clean[field].length > 160) throw new Error(`Asset ${index + 1}: ${field} is too long.`);
      }
      if (!clean.id || !clean.vendor || !clean.product || ids.has(clean.id)) throw new Error('Every asset needs a unique id, vendor, and product.');
      if (!!clean.cpe_vendor !== !!clean.cpe_product) throw new Error('Supply both cpe_vendor and cpe_product, or neither.');
      clean.cpe_part = asset.cpe_part ?? 'a';
      if (!['a', 'o', 'h'].includes(clean.cpe_part)) throw new Error('cpe_part must be a, o, or h.');
      clean.exposure = asset.exposure ?? 'unknown';
      clean.importance = asset.importance ?? 'standard';
      if (!['internet', 'internal', 'unknown'].includes(clean.exposure) || !['critical', 'standard'].includes(clean.importance)) throw new Error('Exposure must be internet/internal/unknown; importance must be critical/standard.');
      ids.add(clean.id);
      return clean;
    });
  };
  // Conservative dotted-numeric comparison; vendor suffixes and SemVer build
  // metadata are not assumed to follow the same ordering across products.
  const compareVersions = (a, b) => {
    if (![a, b].every((v) => typeof v === 'string' && /^\d+(?:\.\d+)*$/.test(v) && v.length <= 160)) return null;
    const left = a.split('.').map(BigInt), right = b.split('.').map(BigInt);
    for (let i = 0; i < Math.max(left.length, right.length); i += 1) {
      const x = left[i] ?? 0n, y = right[i] ?? 0n;
      if (x !== y) return x > y ? 1 : -1;
    }
    return 0;
  };
  const versionMatch = (version, rule, cpeVersion) => {
    if (!version) return null;
    let constrained = false;
    if (cpeVersion !== '*') {
      if (cpeVersion === '-' || /[*?\\]/.test(cpeVersion)) return null;
      constrained = true;
      // Exact CPE attributes are literal vendor versions, not numeric ranges.
      if (version !== cpeVersion) return false;
    }
    let outside = false;
    for (const [field, direction, inclusive] of [
      ['versionStartIncluding', 1, true], ['versionStartExcluding', 1, false],
      ['versionEndIncluding', -1, true], ['versionEndExcluding', -1, false],
    ]) {
      if (rule[field] == null) continue;
      constrained = true;
      const cmp = compareVersions(version, rule[field]);
      if (cmp === null) return null;
      if (cmp * direction < 0 || (!inclusive && cmp === 0)) outside = true;
    }
    return constrained ? !outside : null;
  };
  const productKey = (...parts) => JSON.stringify(parts.map((part) => text(part).toLowerCase()));
  const prepareRecord = (item) => {
    const rules = new Map();
    let complex = false;
    let visited = 0;
    const walk = (node, depth) => {
      if (!node || typeof node !== 'object' || depth > 8 || ++visited > 2000) { complex = true; return; }
      if (node.negate === true || node.operator === 'AND' || (node.operator && node.operator !== 'OR')) complex = true;
      if (Array.isArray(node.cpeMatch)) for (const rule of node.cpeMatch) {
        if (rule?.vulnerable !== true || typeof rule.criteria !== 'string') continue;
        const parts = rule.criteria.split(':');
        if (parts.length !== 13 || parts[0] !== 'cpe' || parts[1] !== '2.3') continue;
        const key = productKey(parts[2], parts[3], parts[4]);
        if (!rules.has(key)) rules.set(key, []);
        rules.get(key).push({ criteria: rule.criteria,
          range: Object.fromEntries(Object.entries(rule).filter(([field]) => field.startsWith('version'))),
          supported: !rule.criteria.includes('\\') && parts.slice(6).every((part) => part === '*'),
          version: parts[5] });
      }
      for (const field of ['nodes', 'children']) if (Array.isArray(node[field])) node[field].forEach((child) => walk(child, depth + 1));
    };
    const configs = item.reports?.nvd?.configurations;
    if (Array.isArray(configs)) configs.forEach((config) => walk(config, 0));
    const kev = item.reports?.cisa_kev;
    return { item, rules, complex, cisaKey: kev && text(kev.vendor) && text(kev.product) ? productKey(kev.vendor, kev.product) : null };
  };
  const evidenceFor = (asset, record) => {
    const { item, rules, complex, cisaKey } = record;
    const vendorMatch = cisaKey === productKey(asset.vendor, asset.product);
    const candidates = (asset.cpe_vendor && asset.cpe_product
      ? rules.get(productKey(asset.cpe_part || 'a', asset.cpe_vendor, asset.cpe_product)) || [] : [])
      .map((rule) => ({ criteria: rule.criteria, range: rule.range,
        match: rule.supported ? versionMatch(asset.version, rule.range, rule.version) : null }));
    if (!vendorMatch && !candidates.length) return null;
    let status = 'needs-verification';
    let reason = 'Exact CISA vendor/product match; affected-version evidence is unavailable or cannot be evaluated.';
    if (candidates.length) {
      if (complex || candidates.some((entry) => entry.match === null)) reason = 'CPE product matched, but complex applicability conditions or unsupported/missing versions require vendor verification.';
      else if (candidates.some((entry) => entry.match)) {
        status = 'version-match'; reason = 'Explicit CPE product mapping and supplied version match a supported NVD rule. Confirm applicability with the vendor.';
      } else {
        status = 'outside-reported-range'; reason = 'Supplied version falls outside the evaluated NVD rules. This is not a declaration that the asset is safe.';
      }
    }
    if (same(item.reports?.nvd?.status, 'rejected')) { status = 'needs-verification'; reason = 'NVD marks this CVE rejected. Review the provider records before taking action.'; }
    return { status, reason, cisa_product_match: !!vendorMatch, nvd_rules: candidates };
  };
  const buildReport = (assets, items, generatedAt) => {
    const findings = [];
    const matched = new Set();
    // Parse each snapshot record once, and retain separate product namespaces
    // so display names cannot collide with explicitly mapped CPE identifiers.
    const records = assets.length ? items.map(prepareRecord) : [];
    const cisaIndex = new Map(), cpeIndex = new Map();
    const index = (map, key, position) => {
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(position);
    };
    records.forEach((record, position) => {
      if (record.cisaKey) index(cisaIndex, record.cisaKey, position);
      for (const key of record.rules.keys()) index(cpeIndex, key, position);
    });
    let truncated = false;
    outer: for (const asset of assets) {
      const candidates = new Set(cisaIndex.get(productKey(asset.vendor, asset.product)) || []);
      if (asset.cpe_vendor && asset.cpe_product) {
        for (const position of cpeIndex.get(productKey(asset.cpe_part || 'a', asset.cpe_vendor, asset.cpe_product)) || []) candidates.add(position);
      }
      // Preserve snapshot order and avoid duplicate findings when both sources match.
      for (const position of [...candidates].sort((a, b) => a - b)) {
        const record = records[position], item = record.item;
        const evidence = evidenceFor(asset, record);
        if (!evidence) continue;
        if (findings.length >= 10000) { truncated = true; break outer; }
        matched.add(asset.id);
        findings.push({ asset, cve_id: item.cve_id, exploitation_status: item.exploitation_status,
          ...evidence, required_action: item.reports?.cisa_kev?.required_action || 'Consult the vendor advisory.',
          reports: item.reports });
      }
    }
    const exploitation = { known_exploited: 0, reported_exploitation: 1, not_established: 2 };
    findings.sort((a, b) => Number(a.status === 'outside-reported-range') - Number(b.status === 'outside-reported-range')
      || (exploitation[a.exploitation_status] ?? 2) - (exploitation[b.exploitation_status] ?? 2)
      || Number(b.asset.exposure === 'internet') - Number(a.asset.exposure === 'internet')
      || Number(b.asset.importance === 'critical') - Number(a.asset.importance === 'critical')
      || a.cve_id.localeCompare(b.cve_id) || a.asset.id.localeCompare(b.asset.id));
    return { schema_version: 1, snapshot_generated_at: generatedAt,
      scope: 'Retained CVE collection only. Inventory and exposure are user supplied; matches are not confirmed exposure. No match does not mean safe.',
      asset_count: assets.length, findings, truncated,
      unmatched_assets: truncated ? [] : assets.filter((asset) => !matched.has(asset.id)) };
  };
  return { parseInventory, compareVersions, versionMatch, buildReport };
});
