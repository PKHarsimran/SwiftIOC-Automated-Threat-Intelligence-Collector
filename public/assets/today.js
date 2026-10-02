/* A local decision layer over the same published snapshots. No extra API fetches. */
(() => {
  'use strict';
  const root = document.querySelector('[data-today]'), core = window.SwiftIOCToday, dashboard = window.SwiftIOCCore;
  if (!root || !core || !dashboard) return;
  const get = (name) => root.querySelector(`[data-today-${name}]`);
  const add = (parent, tag, text, className = '') => {
    const node = document.createElement(tag); node.textContent = text; node.className = className; parent.appendChild(node); return node;
  };
  const button = (parent, text, action) => { const node = add(parent, 'button', text, 'button ghost'); node.type = 'button'; node.addEventListener('click', action); return node; };
  const link = (parent, text, href) => { const node = add(parent, 'a', text); node.href = href; return node; };
  const read = (key) => { try { return JSON.parse(localStorage.getItem(key) || 'null'); } catch { return null; } };
  // Read before dashboard.js advances its baseline. One shared writer avoids
  // duplicating megabytes of provider text in quota-limited browser storage.
  const baselineKey = 'swiftioc-cve-evidence-baseline-v2';
  // Remove only the redundant derived cache from the initial Today release.
  try { localStorage.removeItem('swiftioc-today-baseline-v1'); } catch { /* Storage is optional. */ }
  let baseline = read(baselineKey);
  if (!core.validBaseline(baseline)) baseline = null;
  let snapshot = null, model = null, report = null, groupState = 'loading', newest = 0, loaded = false;
  let watches = dashboard.normaliseBriefing(read('swiftioc-cve-briefing-v1'))?.watches || [];
  let currentItems = [], changes = {}, targets = new Map(), selection = new Set();
  let reviews = read('swiftioc-cve-acknowledged-v2');
  const evidence = (item) => dashboard.vulnerabilityEvidence(item, core.recordFor(model, item.cve_id));
  const openCve = (id) => {
    location.hash = 'vulnerabilities';
    window.dispatchEvent(new CustomEvent('swiftioc:review-cve', { detail: id }));
  };
  function renderPlan() {
    const host = get('plan-result'), chips = get('plan-selected'); host.replaceChildren(); chips.replaceChildren();
    for (const id of selection) button(chips, `Remove ${id}`, () => { selection.delete(id); renderPlan(); });
    const plan = core.patchPlan(currentItems, model, report, [...selection]);
    get('plan-clear').disabled = !selection.size;
    get('plan-export').disabled = !selection.size || !snapshot;
    if (!snapshot) { add(host, 'p', 'Planner paused: a usable vulnerability snapshot is required.'); return; }
    if (!selection.size) { add(host, 'p', 'Select a product or CVE to preview a remediation scenario. Nothing is marked patched or reviewed.'); return; }
    add(host, 'h3', `${plan.selected_cves.length} ${plan.selected_cves.length === 1 ? 'CVE' : 'CVEs'} in this scenario`);
    if (!report) {
      add(host, 'p', 'No inventory loaded: this shows evidence associations only, not affected assets or patch impact.');
      link(host, 'Import an inventory to assess potential impact →', '#exposure-report');
    } else {
      const metrics = add(host, 'div', '', 'today-metrics');
      for (const [value, label] of [[plan.findings_before, 'findings before'], [plan.findings_in_scenario, 'findings in scenario'], [plan.findings_remaining, 'findings remaining']]) {
        const metric = add(metrics, 'div', ''); add(metric, 'strong', value); add(metric, 'span', label);
      }
      add(host, 'p', `${plan.asset_ids.length} assets · ${plan.version_rule_matches} version-rule matches · ${plan.needs_verification} findings still need applicability verification. ${plan.outside_range_excluded} outside-range findings excluded.`);
      if (plan.inventory_truncated) add(host, 'p', 'Partial inventory report: findings were truncated. These counts do not cover every imported asset.', 'today-warning');
      const details = add(host, 'details', ''); add(details, 'summary', 'Assets in this scenario (private to this tab)');
      add(details, 'p', plan.asset_ids.join(', ') || 'No matching pending findings. No match does not mean safe.');
    }
    if (model) {
      const details = add(host, 'details', ''); add(details, 'summary', `${plan.groups.length} groups reported with the selected CVEs`);
      const list = add(details, 'ul', '');
      for (const entry of plan.groups) {
        const row = add(list, 'li', '');
        link(row, entry.group, window.SwiftIOCGroupIntel.url(entry.group, 'cves'));
        row.appendChild(document.createTextNode(` · ${entry.selected_cves.length} selected CVEs · ${entry.other_reported_cves} other reported CVEs remain in the group snapshot`));
      }
    } else add(host, 'p', 'Group evidence unavailable; association impact cannot be assessed.');
    add(host, 'p', plan.scenario, 'today-warning');
    add(host, 'p', 'This does not measure risk reduction or neutralize a group. Verify vendor remediation and rescan assets. Inventory stays in this tab; exports include asset IDs.');
  }
  function renderTargets() {
    targets = new Map(); const select = get('plan-target'); select.replaceChildren();
    const empty = add(select, 'option', 'Choose a product or CVE'); empty.value = '';
    const products = new Map();
    for (const item of currentItems) {
      const kev = item.reports?.cisa_kev;
      if (!kev?.vendor || !kev?.product || (item.reports?.nvd?.status || '').toLowerCase() === 'rejected') continue;
      const key = core.productKey(kev.vendor, kev.product);
      if (!products.has(key)) products.set(key, { name: `${kev.vendor} / ${kev.product}`, ids: [] });
      products.get(key).ids.push(item.cve_id);
    }
    const productGroup = add(select, 'optgroup', ''); productGroup.label = 'Products — all retained CVEs for this product';
    [...products.values()].sort((a, b) => a.name.localeCompare(b.name)).forEach((product, index) => {
      const key = `p:${index}`; targets.set(key, product.ids);
      add(productGroup, 'option', `${product.name} (${product.ids.length} CVEs)`).value = key;
    });
    const cveGroup = add(select, 'optgroup', ''); cveGroup.label = 'Individual CVEs';
    [...currentItems].filter((item) => (item.reports?.nvd?.status || '').toLowerCase() !== 'rejected').sort((a, b) => a.cve_id.localeCompare(b.cve_id)).forEach((item) => {
      targets.set(item.cve_id, [item.cve_id]); add(cveGroup, 'option', `${item.cve_id} · ${(item.title || 'Title unavailable').slice(0, 90)}`).value = item.cve_id;
    });
    selection = new Set([...selection].filter((id) => currentItems.some((item) => item.cve_id === id)));
  }
  function render() {
    get('cards').replaceChildren(); get('health').replaceChildren();
    get('plan-target').disabled = get('plan-add').disabled = !snapshot;
    if (!snapshot) {
      get('status').textContent = loaded ? 'Vulnerability data unavailable or older than the last loaded snapshot. Refresh the CVE collection below; no missing data is treated as safe.' : 'Waiting for the published vulnerability snapshot…';
      renderPlan(); return;
    }
    currentItems = core.catalog(snapshot.items, model);
    const now = Date.now(), time = Date.parse(snapshot.generated_at), groupTime = Date.parse(model?.generatedAt);
    const warnings = [];
    if (core.freshness(snapshot.generated_at, now) === 'stale') warnings.push('The vulnerability snapshot is over 48 hours old.');
    if (!model) warnings.push(`Group evidence ${groupState}; group-based suggestions and change comparison are incomplete.`);
    else if (core.freshness(model.generatedAt, now, 72) === 'stale') warnings.push('The group snapshot is over 72 hours old; associations may have changed.');
    if (report?.truncated) warnings.push('Inventory report is partial: some assets were not fully assessed.');
    get('freshness').textContent = warnings.join(' ');
    const usable = core.freshness(snapshot.generated_at, now) !== 'unavailable' && core.freshness(model?.generatedAt, now, 72) !== 'unavailable';
    const canCompare = usable && baseline && time / 1000 >= baseline.snapshotAt && groupTime >= baseline.groupAt;
    changes = {};
    if (canCompare) for (const item of currentItems) {
      const delta = dashboard.vulnerabilityChanges(baseline.records[item.cve_id], evidence(item));
      if (delta.length) changes[item.cve_id] = delta;
    }
    const reviewed = (item) => reviews?.version === 2 && reviews.snapshotAt <= time / 1000 && reviews.groupAt <= groupTime
      && reviews.records?.[item.cve_id] && dashboard.vulnerabilityChanges(reviews.records[item.cve_id], evidence(item)).length === 0;
    const result = core.recommendations(currentItems, model, { watches, groupWatch: read('swiftioc.ransomwareWatch') || {}, report, changes, reviewed });
    const changedCount = result.ranked.filter((entry) => changes[entry.item.cve_id]).length;
    get('status').textContent = `${result.personal ? 'Personal briefing' : 'Collection highlights — not yet personalized'} · ${result.ranked.length} CVEs in scope · ${canCompare ? `${changedCount} changed since your previous visit` : baseline ? 'Change comparison paused: incomplete or older snapshots' : 'First visit establishes your change baseline'}.`;
    get('setup').hidden = result.personal;
    if (!result.top.length) add(get('cards'), 'p', 'No retained CVEs match your current watches or inventory findings. Check collection coverage; this does not establish safety.');
    for (const entry of result.top) {
      const card = add(get('cards'), 'article', '', 'today-card');
      const labels = add(card, 'div', '', 'today-labels');
      add(labels, 'span', entry.reviewed ? 'Reviewed evidence' : 'Suggested review');
      if (changes[entry.item.cve_id]) add(labels, 'span', 'Evidence changed');
      add(card, 'h3', entry.item.cve_id);
      add(card, 'p', entry.item.title && entry.item.title !== entry.item.cve_id ? entry.item.title : 'Provider details not retained', 'today-title');
      const reasons = add(card, 'ul', ''); entry.reasons.slice(0, 4).forEach((reason) => add(reasons, 'li', reason));
      const profile = core.evidenceProfile(entry.item, model, snapshot.generated_at);
      add(card, 'p', profile.hasVersionRules ? 'Applicability rules available; verify against your installed version.' : 'Affected-version verification needed.', 'today-quality-hint');
      const actions = add(card, 'div', '', 'today-actions');
      button(actions, 'Review evidence', () => openCve(entry.item.cve_id));
      button(actions, 'Try patch scenario', () => { selection.add(entry.item.cve_id); get('planner').open = true; renderPlan(); get('planner').scrollIntoView({ block: 'start' }); });
    }
    const health = get('health');
    add(health, 'p', `Vulnerability snapshot: ${snapshot.generated_at} · ${core.freshness(snapshot.generated_at)} (48-hour freshness window).`);
    add(health, 'p', `Group snapshot: ${model?.generatedAt || groupState} · ${core.freshness(model?.generatedAt, now, 72)} (72-hour freshness window).`);
    const groupItems = currentItems.filter((item) => core.recordFor(model, item.cve_id)?.groups.length);
    const missing = groupItems.filter((item) => !item.reports?.cisa_kev && !item.reports?.nvd);
    add(health, 'p', `${snapshot.items.length} retained CVEs · ${model ? `${groupItems.length} group-linked CVEs · ${missing.length} group-linked CVEs missing retained provider reports` : 'group coverage unavailable'}.`);
    add(health, 'p', `${snapshot.items.filter((item) => Array.isArray(item.reports?.nvd?.configurations) && item.reports.nvd.configurations.length).length} CVEs have structured applicability data. Presence of rules does not guarantee that all conditions can be evaluated.`);
    if (missing.length) {
      const details = add(health, 'details', ''); add(details, 'summary', 'Provider-detail gaps to investigate');
      for (const item of missing.slice(0, 30)) button(details, item.cve_id, () => openCve(item.cve_id));
      if (missing.length > 30) add(details, 'p', `Showing 30 of ${missing.length} gaps.`);
    }
    add(health, 'p', 'Repeated snapshots show continued reporting, not independent corroboration. Snapshot freshness does not date an attack. This view reuses published data and makes no ransomware.live API calls.');
    renderTargets(); renderPlan();
  }
  window.addEventListener('swiftioc:vulnerability-snapshot', (event) => {
    loaded = true;
    const next = event.detail, time = Date.parse(next?.generated_at);
    snapshot = Array.isArray(next?.items) && Number.isFinite(time) && time >= newest && time <= Date.now() ? next : null;
    if (snapshot) newest = time;
    if (report && report.snapshot_generated_at !== snapshot?.generated_at) report = null;
    render();
  });
  window.addEventListener('swiftioc:inventory-report', (event) => { report = event.detail; if (snapshot && report?.snapshot_generated_at !== snapshot.generated_at) report = null; render(); });
  window.addEventListener('swiftioc:briefing-change', (event) => { watches = dashboard.normaliseBriefing(event.detail)?.watches || []; render(); });
  window.addEventListener('swiftioc:review-change', (event) => { reviews = event.detail || read('swiftioc-cve-acknowledged-v2'); render(); });
  window.addEventListener('storage', (event) => {
    if (['swiftioc-cve-briefing-v1', 'swiftioc.ransomwareWatch', 'swiftioc-cve-acknowledged-v2', null].includes(event.key)) {
      watches = dashboard.normaliseBriefing(read('swiftioc-cve-briefing-v1'))?.watches || [];
      reviews = read('swiftioc-cve-acknowledged-v2'); render();
    }
  });
  window.SwiftIOCGroupIntel.ready.then((data) => {
    model = core.freshness(data.generatedAt, Date.now(), 72) === 'unavailable' ? null : data;
    groupState = model ? 'available' : 'invalid timestamp'; render();
  }).catch(() => { groupState = 'unavailable'; render(); });
  get('plan-add').addEventListener('click', () => {
    for (const id of targets.get(get('plan-target').value) || []) selection.add(id);
    renderPlan();
  });
  get('plan-clear').addEventListener('click', () => { selection.clear(); renderPlan(); });
  get('plan-export').addEventListener('click', () => {
    if (!snapshot || !selection.size) return;
    const plan = core.patchPlan(currentItems, model, report, [...selection]); plan.vulnerability_snapshot = snapshot.generated_at;
    const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = 'swiftioc-patch-scenario.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  render();
})();
