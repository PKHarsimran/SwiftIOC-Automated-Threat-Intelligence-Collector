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
  function catalog(items, model, signals = null) {
    const map = new Map(items.map((item) => [item.cve_id, item]));
    for (const record of model?.records || []) if (record.kind === 'cves' && cveId(record.value) && !map.has(record.value)) {
      map.set(record.value, { cve_id: record.value, title: record.value,
        description: 'Reported by ransomware.live, but detailed CISA/NVD evidence is not present in the current retained SwiftIOC vulnerability collection. Verify affected products, versions, severity, and remediation with an authoritative vulnerability record.',
        exploitation_status: 'not_established', reports: {}, sources: ['ransomware.live'] });
    }
    return [...map.values()].map((item) => {
      const signal = signals?.items?.[item.cve_id];
      if (!signal) return item;
      const official = signal.official_cve;
      const missingDetails = !item.reports?.nvd && !item.reports?.cisa_kev;
      return { ...item, signals: signal,
        description: missingDetails && official?.description ? official.description : item.description,
        title: missingDetails && official?.description ? official.description.slice(0, 110) : item.title };
    });
  }
  const recordFor = (model, id) => model?.byIdentity.get(`cve:${id.toLowerCase()}`) || null;
  function evidenceProfile(item, model, snapshotAt, now = Date.now()) {
    const record = recordFor(model, item.cve_id);
    const kev = item.reports?.cisa_kev, nvd = item.reports?.nvd;
    const official = item.signals?.official_cve, epss = item.signals?.epss;
    const groups = record?.groups || [];
    const receipts = Object.values(model?.history?.observations || {}).filter((entry) => entry.kind === 'cves'
      && entry.value === item.cve_id && entry.present === true && groups.includes(entry.group)
      && Number.isFinite(Date.parse(entry.last_observed)) && Date.parse(entry.last_observed) >= 0 && Date.parse(entry.last_observed) <= now);
    const hasVersionRules = Array.isArray(nvd?.configurations) && nvd.configurations.length > 0;
    const gaps = [];
    if (!kev && !nvd && !official) gaps.push('Provider vulnerability details are missing from this retained collection.');
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
        { source: 'Official CVE record', finding: official ? `Published record available${official.cisa_ssvc ? ' with CISA SSVC decision points' : ''}.` : 'No official CVE detail retained in this sidecar.', boundary: 'A CVE record or proof-of-concept label alone does not establish current exploitation or affected local assets.' },
        { source: 'FIRST EPSS', finding: epss ? `${Math.round(epss.probability * 1000) / 10}% estimated 30-day exploitation probability.` : 'No EPSS score retained.', boundary: 'Forecast of observed exploitation activity, not a severity score, current exploitation finding or local risk score.' },
      ],
      corroboration: 'Independent corroboration of the group association is not established. Feed matches and repeated snapshots are not independent sources.' };
  }
  function recommendations(items, model, { watches = [], groupWatch = {}, report = null, changes = {}, reviewed = () => false } = {}, now = Date.now()) {
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
      const epss = item.signals?.epss?.probability;
      if (Number.isFinite(epss) && epss >= 0.2 && item.exploitation_status !== 'known_exploited') {
        reasons.push(`EPSS forecast: ${Math.round(epss * 100)}% chance of observed exploitation in 30 days`); score += 10;
      }
      if (record?.groups.length) { reasons.push(`${record.groups.length} reported group associations`); score += 10; }
      const kevAdded = Date.parse(kev?.date_added);
      if (Number.isFinite(kevAdded) && kevAdded <= now && now - kevAdded <= 30 * DAY) {
        reasons.push('Added to CISA KEV in the last 30 days'); score += 35;
      }
      if (changes[item.cve_id]?.length) { reasons.unshift(changes[item.cve_id].join('; ')); score += 15; }
      if (findings.some((f) => f.asset.exposure === 'internet')) { reasons.push('User-marked internet exposure'); score += 20; }
      if (findings.some((f) => f.asset.importance === 'critical')) { reasons.push('User-marked critical asset'); score += 10; }
      return { item, reasons, score, relevant, reviewed: reviewed(item), findings, kevAdded: Number.isFinite(kevAdded) && kevAdded <= now ? kevAdded : 0 };
    }).filter((entry) => (!personal || entry.relevant) && (entry.item.reports?.nvd?.status || '').toLowerCase() !== 'rejected')
      .sort((a, b) => Number(a.reviewed) - Number(b.reviewed) || b.score - a.score || b.kevAdded - a.kevAdded || a.item.cve_id.localeCompare(b.item.cve_id));
    return { personal, ranked, top: ranked.slice(0, 3) };
  }
  function nextStep(entry) {
    if (entry.findings.some((finding) => finding.status === 'version-match')) return 'Verify the reported affected version on the matched asset, then apply the vendor remediation and rescan.';
    if (entry.findings.length) return 'Check affected versions against the vendor advisory; the inventory match alone is not confirmed exposure.';
    if (entry.item.reports?.cisa_kev) return 'Check whether the affected product is deployed, then follow the vendor and CISA remediation guidance.';
    if (entry.item.signals?.official_cve?.affected?.length) return 'Compare the official CVE affected-product details with your inventory; applicability is not yet established.';
    return 'Check the authoritative CVE and vendor advisory before drawing an exposure conclusion.';
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
    return value?.version === 2 && Number.isFinite(value.snapshotAt) && value.snapshotAt >= 0 && Number.isFinite(value.groupAt) && value.groupAt >= 0
      && value.records && typeof value.records === 'object' && !Array.isArray(value.records) && Object.keys(value.records).length <= 10000
      && Object.entries(value.records).every(([id, evidence]) => cveId(id) && evidence && Array.isArray(evidence.groups)
        && evidence.groups.length <= 1000 && evidence.groups.every((group) => typeof group === 'string' && group.length <= 200));
  }
  return { freshness, catalog, recordFor, productKey, evidenceProfile, recommendations, nextStep, patchPlan, validBaseline, DAY };
});
