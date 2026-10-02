(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SwiftIOCToday = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, () => {
  'use strict';
  const DAY = 86400000;
  const cveId = (value) => /^CVE-\d{4}-\d{4,19}$/.test(value);
  const productKey = (vendor, product) => JSON.stringify([vendor || '', product || ''].map((v) => v.trim().toLowerCase()));
  function freshness(value, now = Date.now(), hours = 48) {
    const time = Date.parse(value);
    return !Number.isFinite(time) || time < 0 || time > now ? 'unavailable' : now - time > hours * 3600000 ? 'stale' : 'current';
  }
  function catalog(items, model) {
    const map = new Map(items.map((item) => [item.cve_id, item]));
    for (const record of model?.records || []) if (record.kind === 'cves' && cveId(record.value) && !map.has(record.value)) {
      map.set(record.value, { cve_id: record.value, title: 'Provider details not retained', exploitation_status: 'not_established', reports: {}, sources: [] });
    }
    return [...map.values()];
  }
  const recordFor = (model, id) => model?.byIdentity.get(`cve:${id.toLowerCase()}`) || null;
  function evidenceProfile(item, model, snapshotAt, now = Date.now()) {
    const record = recordFor(model, item.cve_id);
    const kev = item.reports?.cisa_kev, nvd = item.reports?.nvd;
    const groups = record?.groups || [];
    const receipts = Object.values(model?.history?.observations || {}).filter((entry) => entry.kind === 'cves'
      && entry.value === item.cve_id && entry.present === true && groups.includes(entry.group)
      && Number.isFinite(Date.parse(entry.last_observed)) && Date.parse(entry.last_observed) >= 0 && Date.parse(entry.last_observed) <= now);
    const hasVersionRules = Array.isArray(nvd?.configurations) && nvd.configurations.length > 0;
    const gaps = [];
    if (!kev && !nvd) gaps.push('Provider vulnerability details are missing from this retained collection.');
    if (!hasVersionRules) gaps.push('No structured NVD applicability rules retained; verify affected versions with the vendor.');
    if (!kev?.required_action) gaps.push('No CISA remediation text retained; consult the vendor advisory.');
    if (kev && freshness(kev.catalog_checked_at, now) !== 'current') gaps.push('The KEV catalog-check timestamp is stale or missing; a fresh collection timestamp alone does not revalidate membership.');
    if (groups.length && receipts.length < groups.length) gaps.push('Some group associations lack a current local observation receipt.');
    const vulnerabilityFreshness = freshness(snapshotAt, now);
    const groupFreshness = freshness(model?.generatedAt, now, 72);
    if (vulnerabilityFreshness !== 'current') gaps.push('Vulnerability snapshot is stale or unavailable.');
    if (groups.length && groupFreshness !== 'current') gaps.push('Group snapshot is stale or unavailable.');
    return { groups, vulnerabilityFreshness, groupFreshness, hasVersionRules, receipts: receipts.length, gaps,
      claims: [
        { source: 'ransomware.live', finding: groups.length ? `Reports associations with ${groups.length} groups.` : model ? 'No group association in this snapshot.' : 'Group evidence unavailable.', boundary: 'Reported association; current use and attribution are not established.' },
        { source: 'CISA KEV', finding: kev ? 'Retained KEV report available.' : 'No KEV report retained.', boundary: 'Exploitation evidence does not independently confirm the named group association.' },
        { source: 'NVD', finding: nvd ? `Vulnerability report retained${hasVersionRules ? ' with applicability rules' : ''}.` : 'No NVD report retained.', boundary: 'Descriptions and severity are not proof of exploitation or local exposure.' },
      ],
      corroboration: 'Independent corroboration of the group association is not established. Feed matches and repeated snapshots are not independent sources.' };
  }
  function recommendations(items, model, { watches = [], groupWatch = {}, report = null, changes = {}, reviewed = () => false } = {}) {
    const tokens = (value) => new Set(typeof value === 'string' ? value.split(/[\n,]+/).map((v) => v.trim().toLowerCase()).filter(Boolean) : []);
    const groups = tokens(groupWatch.groups), evidence = tokens(groupWatch.evidence);
    const findingMap = new Map();
    for (const finding of report?.findings || []) if (finding.status !== 'outside-reported-range') {
      if (!findingMap.has(finding.cve_id)) findingMap.set(finding.cve_id, []);
      findingMap.get(finding.cve_id).push(finding);
    }
    const personal = watches.length > 0 || groups.size > 0 || evidence.size > 0 || Boolean(report);
    const ranked = items.map((item) => {
      const record = recordFor(model, item.cve_id), kev = item.reports?.cisa_kev;
      const findings = findingMap.get(item.cve_id) || [];
      const reasons = [];
      let score = 0;
      if (findings.length) { reasons.push(`${new Set(findings.map((f) => f.asset.id)).size} inventory assets need applicability review`); score += 100; }
      if (watches.some((watch) => typeof watch.vendor === 'string' && watch.vendor.trim().toLowerCase() === (kev?.vendor || '').trim().toLowerCase()
        && (!watch.product || productKey(watch.vendor, watch.product) === productKey(kev?.vendor, kev?.product)))) { reasons.push('Matches a watched product or vendor'); score += 50; }
      if (record?.groups.some((group) => groups.has(group.toLowerCase()))) { reasons.push('Associated with a watched group'); score += 40; }
      if (evidence.has(item.cve_id.toLowerCase())) { reasons.push('CVE is on your workbench watchlist'); score += 40; }
      const relevant = score > 0;
      if (item.exploitation_status === 'known_exploited') { reasons.push('Known exploitation evidence'); score += 20; }
      if (record?.groups.length) { reasons.push(`${record.groups.length} reported group associations`); score += 10; }
      if (changes[item.cve_id]?.length) { reasons.push(changes[item.cve_id].join('; ')); score += 15; }
      if (findings.some((f) => f.asset.exposure === 'internet')) { reasons.push('User-marked internet exposure'); score += 20; }
      if (findings.some((f) => f.asset.importance === 'critical')) { reasons.push('User-marked critical asset'); score += 10; }
      return { item, reasons, score, relevant, reviewed: reviewed(item), findings };
    }).filter((entry) => (!personal || entry.relevant) && (entry.item.reports?.nvd?.status || '').toLowerCase() !== 'rejected')
      .sort((a, b) => Number(a.reviewed) - Number(b.reviewed) || b.score - a.score || a.item.cve_id.localeCompare(b.item.cve_id));
    return { personal, ranked, top: ranked.slice(0, 3) };
  }
  function patchPlan(items, model, report, selected) {
    const ids = new Set(selected);
    const chosen = items.filter((item) => ids.has(item.cve_id));
    const validIds = new Set(chosen.map((item) => item.cve_id));
    const pending = (report?.findings || []).filter((finding) => finding.status !== 'outside-reported-range');
    const addressed = pending.filter((finding) => validIds.has(finding.cve_id));
    const remaining = pending.filter((finding) => !validIds.has(finding.cve_id));
    const groups = [...new Set(chosen.flatMap((item) => recordFor(model, item.cve_id)?.groups || []))].sort().map((group) => {
      const records = (model.byGroup.get(group) || []).filter((r) => r.kind === 'cves');
      return { group, selected_cves: records.filter((r) => validIds.has(r.value)).map((r) => r.value),
        other_reported_cves: records.filter((r) => !validIds.has(r.value)).length };
    });
    return { schema_version: 1, scenario: 'Assume the selected CVEs are successfully remediated on every matching imported asset; verify this before taking action.',
      selected_cves: chosen.map((item) => item.cve_id), inventory_loaded: Boolean(report), inventory_truncated: Boolean(report?.truncated),
      findings_before: pending.length, findings_in_scenario: addressed.length, findings_remaining: remaining.length,
      version_rule_matches: addressed.filter((finding) => finding.status === 'version-match').length,
      needs_verification: addressed.filter((finding) => finding.status !== 'version-match').length,
      asset_ids: [...new Set(addressed.map((finding) => finding.asset.id))],
      outside_range_excluded: (report?.findings || []).filter((finding) => finding.status === 'outside-reported-range').length,
      groups, vulnerability_snapshot: report?.snapshot_generated_at || null, group_snapshot: model?.generatedAt || null,
      limitations: ['A simulation, not a patch verification or risk-reduction percentage.', 'Reported group associations do not establish current use or compromise.',
        'Unmatched assets and CVEs outside the retained collection remain unassessed.', 'No findings, watchlists, or review states are changed.'] };
  }
  function validBaseline(value) {
    return value?.version === 1 && Number.isFinite(value.snapshotAt) && value.snapshotAt >= 0 && Number.isFinite(value.groupAt) && value.groupAt >= 0
      && value.records && typeof value.records === 'object' && !Array.isArray(value.records) && Object.keys(value.records).length <= 10000
      && Object.entries(value.records).every(([id, evidence]) => cveId(id) && evidence && Array.isArray(evidence.groups)
        && evidence.groups.length <= 1000 && evidence.groups.every((group) => typeof group === 'string' && group.length <= 200));
  }
  return { freshness, catalog, recordFor, productKey, evidenceProfile, recommendations, patchPlan, validBaseline, DAY };
});
