/* Shared static-evidence model for the group explorer and relationship map. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SwiftIOCGroupCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, () => {
  'use strict';
  const identity = (value, type) => {
    const clean = String(value || '').trim().replaceAll('[.]', '.').replace(/^hxxps:/i, 'https:').replace(/^hxxp:/i, 'http:');
    return type === 'url' ? clean : clean.toLowerCase();
  };
  function build(data) {
    if (data?.schema_version !== 1 || !['groups', 'iocs', 'cves'].every((key) => Array.isArray(data[key]))) throw new Error('Invalid evidence snapshot');
    const groups = new Map(data.groups.filter((g) => typeof g.name === 'string').map((g) => [g.name, g]));
    const techniques = new Map();
    groups.forEach((group) => (group.ttps || []).forEach((id) => {
      if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) return;
      if (!techniques.has(id)) techniques.set(id, new Set());
      techniques.get(id).add(group.name);
    }));
    const records = [];
    for (const kind of ['cves', 'iocs']) for (const item of data[kind]) {
      const value = kind === 'cves' ? item.cve_id : item.indicator;
      if (typeof value !== 'string' || !Array.isArray(item.groups)) continue;
      records.push({ key: `${kind}:${item.type || 'cve'}:${value}`, kind, value,
        type: kind === 'cves' ? 'cve' : item.type, matched: item.in_swiftioc === true,
        groups: [...new Set(item.groups.filter((name) => groups.has(name)))].sort() });
    }
    techniques.forEach((names, value) => records.push({ key: `ttps:${value}`, kind: 'ttps', type: 'technique', value, groups: [...names].sort(), matched: false }));
    records.sort((a, b) => Number(b.matched) - Number(a.matched) || b.groups.length - a.groups.length || a.value.localeCompare(b.value));
    const byGroup = new Map([...groups.keys()].map((name) => [name, records.filter((r) => r.groups.includes(name))]));
    const byIdentity = new Map(records.map((r) => [`${r.type}:${identity(r.value, r.type)}`, r]));
    return { groups, records, byGroup, byIdentity, generatedAt: data.generated_at, history: data.evidence_history || null };
  }
  function filter(model, { group = '', kind = 'cves', query = '', coverage = 'all', type = '' } = {}) {
    const term = query.trim().toLowerCase();
    return (group ? model.byGroup.get(group) || [] : model.records).filter((r) =>
      r.kind === kind && (!type || r.type === type) && (!term || (kind === 'cves' && /^cve-\d{4}-\d{4,19}$/.test(term) ? r.value.toLowerCase() === term : r.value.toLowerCase().includes(term))) &&
      (kind === 'ttps' || coverage === 'all' || (coverage === 'matched' ? r.matched : !r.matched)));
  }
  function graph(model, group, kind = 'cves', selectedKey = '') {
    const all = filter(model, { group, kind });
    const evidence = all.slice(0, 12);
    const requested = all.find((r) => r.key === selectedKey);
    if (requested && !evidence.includes(requested)) evidence[evidence.length - 1] = requested;
    const selected = evidence.find((r) => r.key === selectedKey) || evidence[0] || null;
    const related = selected ? selected.groups.filter((name) => name !== group) : [];
    return { group, evidence, total: all.length, selected, related: related.slice(0, 8), relatedTotal: related.length };
  }
  function receipt(model, record, group) {
    return Object.values(model.history?.observations || {}).find((item) => item.group === group && item.kind === record.kind && item.type === record.type && item.value === record.value) || null;
  }
  function huntPack(model, group, index, earliest, buildSpl) {
    if (!model.groups.has(group)) throw new Error('Select a group first.');
    if (!buildSpl({ type: 'ipv4', indicator: '192.0.2.1' }, index, earliest)) throw new Error('Use valid index names, wildcards, or comma-separated indexes.');
    const records = model.byGroup.get(group);
    return { schema_version: 1, group, source: 'ransomware.live', source_url: `https://ransomware.live/group/${encodeURIComponent(group)}`,
      snapshot_at: model.generatedAt, exported_at: new Date().toISOString(), index, earliest,
      limitations: ['Reported associations do not establish current use or local compromise.', 'Feed matches are not independent corroboration.',
        'Review field mappings and query cost before running. No results do not prove absence.', 'Techniques describe group behavior, not each IOC. This pack is not an automatic blocklist.'],
      ioc_hunts: records.filter((r) => r.kind === 'iocs').map((r) => ({ indicator: r.value, type: r.type, in_swiftioc: r.matched,
        spl: buildSpl({ indicator: r.value, type: r.type }, index, earliest), evidence: receipt(model, r, group) })),
      cve_checklist: records.filter((r) => r.kind === 'cves').map((r) => ({ cve: r.value, in_swiftioc: r.matched,
        steps: ['Confirm affected products and versions using authoritative advisories.', 'Check your asset inventory and exposure.', 'Verify remediation and investigate relevant logs.'], evidence: receipt(model, r, group) })),
      techniques: records.filter((r) => r.kind === 'ttps').map((r) => ({ id: r.value, reference: `https://attack.mitre.org/techniques/${r.value.replace('.', '/')}/`, evidence: receipt(model, r, group) })) };
  }
  return { build, filter, graph, identity, receipt, huntPack };
});
