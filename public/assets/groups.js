(() => {
  'use strict';
  const core = window.SwiftIOCGroupCore;
  const service = window.SwiftIOCGroupIntel;
  const $ = (selector) => document.querySelector(selector);
  const el = (tag, text = '', className = '') => {
    const node = document.createElement(tag); node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const button = (text, action, className = 'group-link-button') => {
    const node = el('button', text, className); node.type = 'button'; node.addEventListener('click', action); return node;
  };
  const link = (text, href, external = false) => {
    const node = el('a', text); node.href = href;
    if (external) { node.target = '_blank'; node.rel = 'noopener noreferrer'; }
    return node;
  };
  let model;
  let state = { view: 'overview', group: '', q: '', coverage: 'all', type: '', mapKind: 'cves' };
  let page = 0;
  let selectedKey = '';
  let currentMap = null;
  let changeLimit = 30;
  const labels = { iocs: 'IOCs', cves: 'CVEs', ttps: 'ATT&CK techniques' };
  function readLocation() {
    if (location.hash === '#group-content') { render(); return; }
    const p = new URLSearchParams(location.hash.slice(1));
    state = { view: ['overview', 'changes', 'hunt', 'cves', 'iocs', 'ttps', 'graph'].includes(p.get('view')) ? p.get('view') : 'overview',
      group: model.groups.has(p.get('group')) ? p.get('group') : '', q: (p.get('q') || '').slice(0, 2048),
      coverage: ['matched', 'new'].includes(p.get('coverage')) ? p.get('coverage') : 'all', type: p.get('type') || '',
      mapKind: ['iocs', 'ttps'].includes(p.get('mapKind')) ? p.get('mapKind') : 'cves', evidence: p.get('evidence') || '' };
    page = 0; selectedKey = state.evidence;
    render();
  }
  function navigate(change, replace = false) {
    state = { ...state, ...change, evidence: change.evidence || '' }; page = 0; selectedKey = state.evidence;
    render();
    const p = new URLSearchParams(Object.entries(state).filter(([, value]) => value));
    history[replace ? 'replaceState' : 'pushState'](null, '', `#${p}`);
  }
  function selectGroup(name) {
    $('[data-group-help]').textContent = 'Select a suggestion to focus the evidence.';
    navigate({ group: name, q: '', coverage: 'all', type: '' });
  }
  function groupLinks(names) {
    const wrap = el('div', '', 'group-inline-links');
    const add = (host, name) => host.appendChild(button(name, () => selectGroup(name)));
    names.slice(0, 2).forEach((name) => add(wrap, name));
    if (names.length > 2) {
      const details = el('details'); details.appendChild(el('summary', `+${names.length - 2} groups`));
      const rest = el('div', '', 'group-inline-links'); names.slice(2).forEach((name) => add(rest, name)); details.appendChild(rest); wrap.appendChild(details);
    }
    return wrap;
  }
  function investigate(record) {
    if (record.kind === 'ttps') return link('ATT&CK ↗', `https://attack.mitre.org/techniques/${record.value.replace('.', '/')}/`, true);
    return link(record.kind === 'cves' ? 'Review CVE →' : 'Check feed →', `index.html#ioc=${encodeURIComponent(record.value)}`);
  }
  function evidenceReceipt(record) {
    const details = el('details'); details.appendChild(el('summary', 'Evidence receipt'));
    details.appendChild(el('p', `Source: ransomware.live · Provider snapshot: ${model.generatedAt}. ${record.kind === 'ttps' ? 'Group-level behavior only.' : record.matched ? 'Exact type/value match in the retained SwiftIOC feed; not independent corroboration.' : 'Research candidate; not automatically promoted into the feed.'}`, 'group-small'));
    const names = state.group && record.groups.includes(state.group) ? [state.group] : record.groups;
    names.forEach((name) => {
      const observation = core.receipt(model, record, name);
      const row = el('p', '', 'group-small'); row.appendChild(link(name, `https://ransomware.live/group/${encodeURIComponent(name)}`, true));
      row.appendChild(document.createTextNode(observation ? ` · First observed locally: ${observation.first_observed} · Last local check: ${observation.last_observed}` : ' · Observation history not available yet.'));
      details.appendChild(row);
    });
    details.appendChild(el('p', 'Local observation dates are not attack dates. This association does not establish current use, local compromise, or independent confirmation.', 'group-small'));
    return details;
  }
  function renderChanges() {
    const history = model.history;
    const cutoff = Date.now() - Number($('[data-change-days]').value) * 86400000;
    const events = (history?.events || []).filter((event) => (!state.group || event.group === state.group) && Date.parse(event.at) >= cutoff).slice().reverse();
    $('[data-change-status]').textContent = history ? `${events.length} changes in this window. Tracking began ${new Date(history.started_at).toLocaleString()}. History retains up to 90 days / 5,000 events.${history.truncated ? ' Older events were truncated.' : ''}` : 'Observation tracking begins with the next collection. Existing evidence will establish a baseline, not a new-activity alert.';
    const list = $('[data-change-list]'); list.replaceChildren();
    const actions = { added: 'Association added', returned: 'Association returned', removed: 'No longer in snapshot', matched: 'Now matches SwiftIOC feed' };
    events.slice(0, changeLimit).forEach((event) => {
      const row = el('div', '', 'group-short-row');
      const description = el('div'); description.append(el('strong', actions[event.action] || event.action), el('p', `${event.value} · ${event.group}`, 'group-small'), el('small', new Date(event.at).toLocaleString()));
      row.appendChild(description);
      if (model.groups.has(event.group)) row.appendChild(button('Explore group', () => navigate({ group: event.group, view: 'overview' })));
      list.appendChild(row);
    });
    if (!events.length) list.appendChild(el('p', 'No recorded changes in this selection. This does not establish inactivity.'));
    $('[data-change-more]').hidden = events.length <= changeLimit;
  }
  function renderHunt() {
    const records = model.byGroup.get(state.group) || [];
    $('[data-hunt-status]').textContent = state.group ? `${state.group}: ${records.filter((r) => r.kind === 'iocs').length} IOC searches, ${records.filter((r) => r.kind === 'cves').length} CVE checks, ${records.filter((r) => r.kind === 'ttps').length} technique references.` : 'Select a group above to build a focused hunt pack.';
    $('[data-hunt-download]').disabled = !state.group;
  }
  function downloadJson(value, filename) {
    const href = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
    const a = link('', href); a.download = filename; a.click(); setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  function renderOverview() {
    const records = state.group ? model.byGroup.get(state.group) : model.records;
    const metrics = $('[data-overview-metrics]'); metrics.replaceChildren();
    for (const kind of ['cves', 'iocs', 'ttps']) {
      const matches = records.filter((r) => r.kind === kind);
      const card = button('', () => navigate({ view: kind, q: '', coverage: 'all', type: '' }), 'group-metric');
      card.append(el('strong', matches.length.toLocaleString()), el('span', labels[kind]), el('small', kind === 'ttps' ? 'Reported techniques' : `${matches.filter((r) => r.matched).length} also in SwiftIOC`)); metrics.appendChild(card);
    }
    const shortlist = $('[data-overview-groups]'); shortlist.replaceChildren();
    $('[data-overview-title]').textContent = state.group ? 'Reported techniques' : 'Start with a group';
    if (state.group) {
      const ttps = records.filter((r) => r.kind === 'ttps');
      const chips = el('div', '', 'group-inline-links'); ttps.slice(0, 8).forEach((r) => chips.appendChild(link(r.value, `https://attack.mitre.org/techniques/${r.value.replace('.', '/')}/`, true)));
      shortlist.appendChild(chips);
      if (!ttps.length) shortlist.appendChild(el('p', 'No techniques in this snapshot.', 'group-small'));
      if (ttps.length > 8) shortlist.appendChild(button(`View all ${ttps.length} techniques →`, () => navigate({ view: 'ttps', q: '' })));
      shortlist.appendChild(button('Open the evidence map →', () => navigate({ view: 'graph' })));
      shortlist.appendChild(link('Group source ↗', `https://ransomware.live/group/${encodeURIComponent(state.group)}`, true));
    } else {
      const ranked = [...model.groups.keys()].sort((a, b) => model.byGroup.get(b).length - model.byGroup.get(a).length || a.localeCompare(b));
      ranked.slice(0, 6).forEach((name) => {
        const row = el('div', '', 'group-short-row'); const records = model.byGroup.get(name);
        row.append(button(name, () => selectGroup(name)), el('span', `${records.filter((r) => r.kind === 'cves').length} CVEs · ${records.filter((r) => r.kind === 'iocs').length} IOCs · ${records.filter((r) => r.kind === 'ttps').length} techniques`, 'group-small')); shortlist.appendChild(row);
      });
      shortlist.appendChild(el('p', `Six groups with the most records shown. Search above to explore any of ${model.groups.size} groups. Record volume is not a risk ranking.`, 'group-small'));
    }
    const cveList = $('[data-overview-cves]'); cveList.replaceChildren();
    const cves = records.filter((r) => r.kind === 'cves');
    cves.slice(0, 5).forEach((r) => {
      const row = el('div', '', 'group-short-row'); row.append(button(r.value, () => navigate({ view: 'cves', q: r.value, coverage: 'all' })), el('span', r.matched ? 'In SwiftIOC' : 'Research candidate', 'group-small')); cveList.appendChild(row);
    });
    if (!cves.length) cveList.appendChild(el('p', 'No reported CVEs for this selection.', 'group-small'));
    else cveList.appendChild(button(`Explore ${cves.length} CVEs →`, () => navigate({ view: 'cves', q: '', coverage: 'all' })));
  }
  function renderRecords() {
    const kind = state.view;
    const scoped = core.filter(model, { group: state.group, kind, query: state.q, type: kind === 'iocs' ? state.type : '' });
    const matched = scoped.filter((r) => r.matched).length;
    const coverage = $('[data-record-coverage]');
    coverage.options[1].textContent = `In SwiftIOC (${matched})`; coverage.options[1].disabled = matched === 0;
    coverage.options[2].textContent = `Research candidates (${scoped.length - matched})`; coverage.options[2].disabled = scoped.length === matched;
    coverage.value = state.coverage;
    $('[data-coverage-label]').hidden = kind === 'ttps'; $('[data-type-label]').hidden = kind !== 'iocs';
    $('[data-record-type]').value = state.type;
    $('[data-record-search]').value = state.q;
    $('[data-record-search]').placeholder = kind === 'ttps' ? 'Technique ID…' : kind === 'cves' ? 'CVE ID…' : 'IP, domain, URL or hash…';
    const records = core.filter(model, { group: state.group, kind, query: state.q, coverage: state.coverage, type: kind === 'iocs' ? state.type : '' });
    const pages = Math.ceil(records.length / 20); page = Math.max(0, Math.min(page, pages - 1));
    $('[data-record-status]').textContent = `${records.length.toLocaleString()} ${labels[kind]}${state.group ? ` linked to ${state.group}` : ' across all groups'} · ${records.length ? '20 records per page.' : 'No matches. Try another group or clear the filters.'}`;
    const body = $('[data-record-rows]'); body.replaceChildren();
    records.slice(page * 20, page * 20 + 20).forEach((r) => {
      const row = el('tr'); const value = el('td'); value.append(el('code', r.value), el('small', r.type, 'group-small'));
      const groups = el('td'); groups.appendChild(groupLinks(r.groups));
      const actions = el('td'); actions.appendChild(investigate(r));
      actions.appendChild(button('Map connection', () => {
        navigate({ view: 'graph', group: state.group || r.groups[0] || '', mapKind: r.kind, evidence: r.key });
      }));
      actions.appendChild(evidenceReceipt(r));
      row.append(value, el('td', kind === 'ttps' ? 'Group behavior' : r.matched ? 'In SwiftIOC' : 'Research candidate'), groups, actions); body.appendChild(row);
    });
    $('[data-page-label]').textContent = `Page ${pages ? page + 1 : 0} of ${pages}`;
    $('[data-prev]').disabled = page === 0; $('[data-next]').disabled = !pages || page + 1 >= pages;
  }
  const svgElement = (tag, attrs, text) => {
    const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attrs).forEach(([key, value]) => n.setAttribute(key, value)); if (text) n.textContent = text; return n;
  };
  function selectEvidence(key, focus = false) {
    selectedKey = key; state.evidence = key; renderGraph();
    history.replaceState(null, '', `#${new URLSearchParams(Object.entries(state).filter(([, value]) => value))}`);
    if (focus) $('[data-map]').querySelector(`.map-node.is-selected[data-kind="${state.mapKind}"]`)?.focus();
  }
  function renderGraph() {
    if (!state.group) state.group = [...model.groups.keys()].sort((a, b) => core.filter(model, { group: b, kind: state.mapKind }).length - core.filter(model, { group: a, kind: state.mapKind }).length)[0] || '';
    const graph = core.graph(model, state.group, state.mapKind, selectedKey); currentMap = graph; selectedKey = graph.selected?.key || '';
    $('[data-map-kind]').value = state.mapKind;
    const choice = $('[data-map-evidence]'); choice.replaceChildren();
    graph.evidence.forEach((r) => { const option = el('option', r.value); option.value = r.key; choice.appendChild(option); }); choice.value = selectedKey; choice.disabled = !graph.selected;
    $('[data-map-status]').textContent = `Showing ${graph.evidence.length} of ${graph.total} ${labels[state.mapKind]} for ${state.group}. ${graph.related.length} of ${graph.relatedTotal} other groups shown for the selected record. ${graph.total > 12 ? 'Use the evidence table for all records.' : ''}`;
    const svg = $('[data-map]'); svg.replaceChildren();
    const height = Math.max(330, graph.evidence.length * 44 + 100, graph.related.length * 44 + 100); svg.setAttribute('viewBox', `0 0 1000 ${height}`);
    svg.setAttribute('aria-label', `Reported associations: ${state.group}, ${graph.evidence.length} ${labels[state.mapKind]}, and ${graph.related.length} other groups`);
    for (const [x, text] of [[20, 'FOCUS GROUP'], [360, 'REPORTED EVIDENCE'], [750, 'ALSO REPORTED FOR']]) svg.appendChild(svgElement('text', { x, y: 24, class: 'map-heading' }, text));
    const node = (x, y, text, active, action, type) => {
      const g = svgElement('g', { transform: `translate(${x} ${y})`, tabindex: '0', role: 'button', 'aria-label': text, class: `map-node ${active ? 'is-selected' : ''}`, 'data-kind': type });
      g.appendChild(svgElement('title', {}, text)); g.appendChild(svgElement('rect', { width: 230, height: 34, rx: 6 }));
      g.appendChild(svgElement('text', { x: 12, y: 22 }, text.length > 25 ? `${text.slice(0, 22)}…` : text));
      g.addEventListener('click', action); g.addEventListener('keydown', (event) => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); action(); } }); svg.appendChild(g);
    };
    const edge = (x1, y1, x2, y2, active) => svg.appendChild(svgElement('path', { d: `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`, class: `map-edge ${active ? 'is-selected' : ''}` }));
    graph.evidence.forEach((r, index) => edge(250, height / 2, 360, 60 + index * 44 + 17, r.key === selectedKey));
    const selectedY = 77 + Math.max(0, graph.evidence.findIndex((r) => r.key === selectedKey)) * 44;
    graph.related.forEach((name, index) => edge(590, selectedY, 750, height / 2 + (index - (graph.related.length - 1) / 2) * 44, true));
    node(20, height / 2 - 17, state.group, true, () => navigate({ view: 'overview' }), 'group');
    graph.evidence.forEach((r, index) => node(360, 60 + index * 44, r.value, r.key === selectedKey, () => selectEvidence(r.key, true), r.kind));
    graph.related.forEach((name, index) => node(750, height / 2 + (index - (graph.related.length - 1) / 2) * 44 - 17, name, false, () => selectGroup(name), 'group'));
    const inspector = $('[data-map-inspector]'); inspector.replaceChildren();
    if (graph.selected) {
      inspector.append(el('strong', graph.selected.value), el('p', 'Reported associations from ransomware.live. Shared evidence alone does not establish a campaign or collaboration.', 'group-small'), groupLinks(graph.selected.groups), investigate(graph.selected));
      inspector.appendChild(evidenceReceipt(graph.selected));
    } else inspector.appendChild(el('p', 'No evidence of this type in the snapshot. Choose another evidence type or group.'));
    $('[data-map-export]').disabled = !graph.selected;
  }
  function render() {
    if (state.view === 'graph') renderGraph();
    $('[data-group-choice]').value = state.group;
    const active = $('[data-active-group]'); active.replaceChildren();
    active.append(el('h2', state.group || 'All groups'), el('span', 'Reported associations · current use is not established', 'group-small'));
    document.querySelectorAll('[data-view]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === state.view)));
    document.querySelectorAll('[data-panel]').forEach((panel) => { panel.hidden = panel.dataset.panel !== (['iocs', 'cves', 'ttps'].includes(state.view) ? 'records' : state.view); });
    if (state.view === 'overview') renderOverview();
    else if (state.view === 'changes') renderChanges();
    else if (state.view === 'hunt') renderHunt();
    else if (state.view !== 'graph') renderRecords();
  }
  service.ready.then((result) => {
    model = result;
    const age = Date.now() - new Date(model.generatedAt).getTime();
    $('[data-page-status]').textContent = `Source snapshot ${new Date(model.generatedAt).toLocaleString()} · ${age > 48 * 3600000 ? 'Refresh delayed; showing retained evidence.' : 'Provider data refreshes daily.'}`;
    model.groups.forEach((_, name) => { const option = el('option', name); option.value = name; $('#group-suggestions').appendChild(option); });
    [...new Set(model.records.filter((r) => r.kind === 'iocs').map((r) => r.type))].sort().forEach((type) => { const option = el('option', type); option.value = type; $('[data-record-type]').appendChild(option); });
    $('[data-explorer]').hidden = false; readLocation();
    window.addEventListener('popstate', readLocation); window.addEventListener('hashchange', readLocation);
    document.querySelectorAll('[data-view]').forEach((b) => b.addEventListener('click', () => navigate({ view: b.dataset.view, q: '', coverage: 'all', type: '' })));
    const applyGroup = () => {
      const value = $('[data-group-choice]').value.trim();
      const match = [...model.groups.keys()].find((name) => name.toLowerCase() === value.toLowerCase());
      if (!value) navigate({ group: '', view: state.view === 'graph' ? 'overview' : state.view });
      else if (match) { if (state.group !== match) selectGroup(match); }
      else $('[data-group-help]').textContent = 'No exact group found. Choose a name from the suggestions.';
    };
    $('[data-group-form]').addEventListener('submit', (event) => { event.preventDefault(); applyGroup(); });
    $('[data-group-choice]').addEventListener('change', applyGroup);
    $('[data-clear-group]').addEventListener('click', () => { $('[data-group-help]').textContent = 'Select a suggestion to focus the evidence.'; navigate({ group: '', view: state.view === 'graph' ? 'overview' : state.view, q: '', coverage: 'all', type: '' }); });
    $('[data-record-search]').addEventListener('input', (event) => navigate({ q: event.target.value }, true));
    $('[data-record-coverage]').addEventListener('change', (event) => navigate({ coverage: event.target.value }));
    $('[data-record-type]').addEventListener('change', (event) => navigate({ type: event.target.value }));
    $('[data-prev]').addEventListener('click', () => { page--; renderRecords(); });
    $('[data-next]').addEventListener('click', () => { page++; renderRecords(); });
    $('[data-change-days]').addEventListener('change', () => { changeLimit = 30; renderChanges(); });
    $('[data-change-more]').addEventListener('click', () => { changeLimit += 30; renderChanges(); });
    $('[data-hunt-download]').addEventListener('click', () => {
      try {
        const pack = core.huntPack(model, state.group, $('[data-hunt-index]').value, $('[data-hunt-window]').value, window.SwiftIOCCore.buildSplQuery);
        downloadJson(pack, `swiftioc-hunt-${state.group.replace(/[^a-z0-9_-]/gi, '_')}.json`);
        $('[data-hunt-status]').textContent = 'Hunt pack exported. Review the queries and field mappings before use.';
      } catch (error) { $('[data-hunt-status]').textContent = error.message; }
    });
    $('[data-map-kind]').addEventListener('change', (event) => navigate({ mapKind: event.target.value }));
    $('[data-map-evidence]').addEventListener('change', (event) => selectEvidence(event.target.value));
    $('[data-map-export]').addEventListener('click', () => {
      if (!currentMap) return;
      const nodes = [{ id: `group:${currentMap.group}`, type: 'group', value: currentMap.group }, ...currentMap.evidence.map((r) => ({ id: r.key, type: r.type, value: r.value })), ...currentMap.related.map((name) => ({ id: `group:${name}`, type: 'group', value: name }))];
      const edges = [...currentMap.evidence.map((r) => ({ from: `group:${currentMap.group}`, to: r.key })), ...currentMap.related.map((name) => ({ from: `group:${name}`, to: currentMap.selected.key }))];
      const blob = new Blob([JSON.stringify({ source: 'ransomware.live', generated_at: model.generatedAt, relationship: 'reported association', nodes, edges }, null, 2)], { type: 'application/json' });
      const href = URL.createObjectURL(blob); const a = link('', href); a.download = 'swiftioc-group-map.json'; a.click(); setTimeout(() => URL.revokeObjectURL(href), 1000);
    });
  }).catch(() => { $('[data-page-status]').textContent = 'Group evidence could not be loaded. Reload this page to try again, or return to the intelligence desk.'; });
})();
