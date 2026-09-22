(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SwiftIOCRansomwareWorkbench = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, () => {
  'use strict';
  const DAY = 86400000;
  const TELEMETRY = {
    'T1003': ['endpoint', 'identity'], 'T1003.001': ['endpoint', 'identity'], 'T1018': ['endpoint', 'network'],
    'T1021.001': ['endpoint', 'identity'], 'T1027': ['endpoint'], 'T1041': ['network', 'proxy'],
    'T1046': ['network'], 'T1053.005': ['endpoint'], 'T1059': ['endpoint'], 'T1059.001': ['endpoint'],
    'T1071.001': ['proxy', 'network'], 'T1078': ['identity'], 'T1082': ['endpoint'], 'T1083': ['endpoint'],
    'T1105': ['endpoint', 'network'], 'T1112': ['endpoint'], 'T1133': ['identity', 'network'],
    'T1136.001': ['identity'], 'T1140': ['endpoint'], 'T1190': ['network'], 'T1219': ['endpoint', 'network'],
    'T1486': ['endpoint'], 'T1490': ['endpoint'], 'T1547.001': ['endpoint'], 'T1562.001': ['endpoint'],
    'T1566.001': ['email'], 'T1567.002': ['proxy', 'cloud'], 'T1570': ['endpoint', 'network'],
  };
  const historyEvents = (model) => model.history?.events || [];
  function priority(record, model, now = Date.now()) {
    const reasons = [];
    let score = 10;
    if (record.matched) { score += 30; reasons.push('Exact type/value match in the retained SwiftIOC feed (+30)'); }
    const groupPoints = Math.min(25, record.groups.length * 5);
    score += groupPoints; reasons.push(`${record.groups.length} reported group association${record.groups.length === 1 ? '' : 's'} (+${groupPoints})`);
    if (record.kind === 'cves') { score += 10; reasons.push('CVE supports exposure review (+10)'); }
    const recent = historyEvents(model).some((event) => event.kind === record.kind && event.type === record.type && event.value === record.value && now - Date.parse(event.at) <= 30 * DAY && ['added', 'returned', 'matched'].includes(event.action));
    if (recent) { score += 20; reasons.push('Locally observed change in the last 30 days (+20)'); }
    if (record.groups.length > 1) { score += 5; reasons.push('Shared reported evidence; attribution needs care (+5)'); }
    score = Math.min(100, score);
    return { score, level: score >= 70 ? 'high' : score >= 40 ? 'medium' : 'review', reasons };
  }
  function quality(record, model) {
    const reasons = ['Typed exact value preserved (+30)', 'Provider snapshot timestamp available (+25)', 'Reported group provenance available (+15)', 'Present in the current snapshot (+10)'];
    let score = 80;
    const observed = Object.values(model.history?.observations || {}).some((item) => item.kind === record.kind && item.type === record.type && item.value === record.value);
    if (observed) { score += 20; reasons.push('Local first/last observation receipt available (+20)'); }
    else reasons.push('Local observation receipt is not available yet (+0)');
    return { score, reasons, meaning: 'Evidence completeness and traceability—not truth, attribution confidence, or compromise probability.' };
  }
  const setFor = (model, group, kind) => new Set((model.byGroup.get(group) || []).filter((r) => r.kind === kind).map((r) => `${r.type}:${r.value}`));
  const intersection = (a, b) => [...a].filter((value) => b.has(value)).length;
  function similarities(model, focus) {
    if (!model.groups.has(focus)) return [];
    const base = Object.fromEntries(['ttps', 'cves', 'iocs'].map((kind) => [kind, setFor(model, focus, kind)]));
    return [...model.groups.keys()].filter((name) => name !== focus).map((name) => {
      const shared = {}; let score = 0;
      for (const [kind, weight] of [['ttps', .5], ['cves', .3], ['iocs', .2]]) {
        const candidate = setFor(model, name, kind); const same = intersection(base[kind], candidate);
        const union = new Set([...base[kind], ...candidate]).size;
        shared[kind] = same; score += union ? (same / union) * weight : 0;
      }
      return { group: name, score: Math.round(score * 100), shared };
    }).filter((item) => item.score || Object.values(item.shared).some(Boolean)).sort((a, b) => b.score - a.score || a.group.localeCompare(b.group));
  }
  function coverage(model, group, available = []) {
    const have = new Set(available);
    return (model.byGroup.get(group) || []).filter((r) => r.kind === 'ttps').map((record) => {
      const required = TELEMETRY[record.value] || [];
      return { technique: record.value, required, status: !required.length ? 'unmapped' : required.some((item) => have.has(item)) ? 'searchable' : 'gap' };
    });
  }
  function groupSignals(model, group, now = Date.now()) {
    const records = model.byGroup.get(group) || [];
    const recent = historyEvents(model).filter((e) => e.group === group && now - Date.parse(e.at) <= 30 * DAY);
    const iocChanges = recent.filter((e) => e.kind === 'iocs' && ['added', 'returned', 'removed'].includes(e.action)).length;
    const iocs = records.filter((r) => r.kind === 'iocs').length;
    return { group, cves: records.filter((r) => r.kind === 'cves').length, iocs,
      techniques: records.filter((r) => r.kind === 'ttps').length, changes30d: recent.length,
      churn: iocs ? Math.min(100, Math.round((iocChanges / iocs) * 100)) : 0 };
  }
  function anomalies(model, now = Date.now()) {
    const recent = new Map(); const previous = new Map();
    historyEvents(model).forEach((event) => {
      const age = now - Date.parse(event.at);
      if (age >= 0 && age <= 7 * DAY) recent.set(event.group, (recent.get(event.group) || 0) + 1);
      else if (age > 7 * DAY && age <= 30 * DAY) previous.set(event.group, (previous.get(event.group) || 0) + 1);
    });
    return [...recent].map(([group, count]) => {
      const baseline = (previous.get(group) || 0) / 23 * 7;
      return { group, count, baseline: Math.round(baseline * 10) / 10, ratio: baseline ? Math.round((count / baseline) * 10) / 10 : null };
    }).filter((item) => item.count >= 2 && (item.ratio === null || item.ratio >= 2)).sort((a, b) => b.count - a.count);
  }
  function triage(model, value) {
    const term = String(value || '').trim();
    const group = [...model.groups.keys()].find((name) => name.toLowerCase() === term.toLowerCase());
    if (group) return { kind: 'group', group, signals: groupSignals(model, group), records: model.byGroup.get(group) };
    const lower = term.toLowerCase();
    const records = model.records.filter((r) => r.value.toLowerCase() === lower || (r.type === 'url' && r.value === term));
    return records.length ? { kind: 'evidence', records } : null;
  }
  function exposure(model, text) {
    const tokens = [...new Set(String(text || '').split(/[\s,;]+/).map((v) => v.trim()).filter(Boolean))];
    const found = []; const unknown = [];
    tokens.forEach((token) => {
      const result = triage(model, token);
      if (result) found.push({ token, result }); else unknown.push(token);
    });
    return { found, unknown };
  }
  const safe = (value) => String(value).replace(/["'\\\r\n]/g, '');
  function detectionDraft(record) {
    const value = safe(record.value ?? record.indicator); const fields = { ipv4: ['SourceIp', 'DestinationIp'], ipv6: ['SourceIp', 'DestinationIp'], domain: ['DnsQuery', 'DestinationHostname'], url: ['Url'], md5: ['MD5'], sha1: ['SHA1'], sha256: ['SHA256'] };
    const mapped = fields[record.type] || ['Indicator'];
    const kql = mapped.map((field) => `${field} == "${value}"`).join(' or ');
    const detection = { condition: '1 of selection_*' };
    mapped.forEach((field, index) => { detection[`selection_${index + 1}`] = { [field]: value }; });
    const sigma = { title: `SwiftIOC ${record.type} investigation draft`, status: 'experimental', logsource: { category: 'review_required' }, detection, falsepositives: ['Review context and local field mappings'], level: 'high' };
    return { kql, sigma, draft: true, review_required: true };
  }
  function responsePack(model, group, index, earliest, detectionCore) {
    const base = windowSafeHunt(model, group, index, earliest, detectionCore.buildSplQuery);
    base.ioc_hunts = base.ioc_hunts.map((item) => ({ ...item, ...detectionDraft(item) }));
    const detectionRows = base.ioc_hunts.map((item) => ({ type: item.type, indicator: item.indicator }));
    base.sigma_rules = detectionCore.rowsToSigma(detectionRows);
    base.suricata_rules = detectionCore.rowsToSuricata(detectionRows);
    base.review = { automatic_blocking: false, deployable_without_review: false, notes: 'Draft field mappings and Suricata SIDs must be reviewed and made unique.' };
    return base;
  }
  function windowSafeHunt(model, group, index, earliest, buildSpl) {
    if (!model.groups.has(group)) throw new Error('Select a group first.');
    if (!buildSpl({ type: 'ipv4', indicator: '192.0.2.1' }, index, earliest)) throw new Error('Invalid index scope.');
    const records = model.byGroup.get(group); const allIocs = records.filter((r) => r.kind === 'iocs'); const selectedIocs = allIocs.slice(0, 500);
    return { schema_version: 1, group, source: 'ransomware.live', snapshot_at: model.generatedAt, exported_at: new Date().toISOString(),
      selection: { iocs_total: allIocs.length, iocs_included: selectedIocs.length, iocs_omitted: allIocs.length - selectedIocs.length },
      ioc_hunts: selectedIocs.map((r) => ({ indicator: r.value, type: r.type, groups: r.groups, in_swiftioc: r.matched, spl: buildSpl({ indicator: r.value, type: r.type }, index, earliest) })),
      cve_checklist: records.filter((r) => r.kind === 'cves').map((r) => ({ cve: r.value, priority: priority(r, model), steps: ['Confirm affected product/version', 'Check asset inventory and exposure', 'Verify remediation', 'Investigate relevant telemetry'] })),
      techniques: records.filter((r) => r.kind === 'ttps').map((r) => ({ id: r.value, telemetry: TELEMETRY[r.value] || [], reference: `https://attack.mitre.org/techniques/${r.value.replace('.', '/')}/` })),
      limitations: ['Reported association is not proof of current use, compromise or attribution.', 'Draft detections require local validation.', 'A negative search does not prove absence.'] };
  }
  function watchMatches(model, context, watch) {
    const wanted = (value) => new Set(String(value || '').split(/[\n,]+/).map((v) => v.trim().toLowerCase()).filter(Boolean));
    const groups = wanted(watch.groups); const evidence = wanted(watch.evidence); const countries = wanted(watch.countries); const sectors = wanted(watch.sectors);
    return { groups: [...model.groups.keys()].filter((name) => groups.has(name.toLowerCase())),
      evidence: model.records.filter((r) => evidence.has(r.value.toLowerCase())),
      countries: (context?.activity?.countries || []).filter((r) => countries.has(r.name.toLowerCase())),
      sectors: (context?.activity?.sectors || []).filter((r) => sectors.has(r.name.toLowerCase())) };
  }
  return { priority, quality, similarities, coverage, groupSignals, anomalies, triage, exposure, detectionDraft, responsePack, watchMatches, TELEMETRY };
});
