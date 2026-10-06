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
  let state = { view: 'overview', group: '', q: '', coverage: 'all', type: '', mapKind: 'cves', layout: 'lanes' };
  let page = 0;
  let selectedKey = '';
  let currentMap = null;
  let mapCy = null;
  let mapSceneKey = '';
  let mapHover = '';
  let mapAllLinks = false;
  let renderedMapLayout = '';
  let changeLimit = 30;
  const labels = { iocs: 'IOCs', cves: 'CVEs', ttps: 'ATT&CK techniques' };
  function readLocation() {
    if (location.hash === '#group-content') { render(); return; }
    const p = new URLSearchParams(location.hash.slice(1));
    state = { view: ['overview', 'changes', 'hunt', 'cves', 'iocs', 'ttps', 'graph'].includes(p.get('view')) ? p.get('view') : 'overview',
      group: model.groups.has(p.get('group')) ? p.get('group') : '', q: (p.get('q') || '').slice(0, 2048),
      coverage: ['matched', 'new'].includes(p.get('coverage')) ? p.get('coverage') : 'all', type: p.get('type') || '',
      mapKind: ['iocs', 'ttps'].includes(p.get('mapKind')) ? p.get('mapKind') : 'cves',
      layout: p.get('layout') === 'orbit' ? 'orbit' : 'lanes', evidence: p.get('evidence') || '' };
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
    return link(record.kind === 'cves' ? 'Review CVE →' : 'Check feed →',
      `index.html#${record.kind === 'cves' ? 'cve' : 'ioc'}=${encodeURIComponent(record.value)}`);
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
    if (focus && !mapCy) $('[data-map]').querySelector(`.map-node.is-selected[data-kind="${state.mapKind}"]`)?.focus();
  }
  function mapPositions(graph, layout) {
    const positions = new Map();
    positions.set(`group:${graph.group}`, layout === 'orbit' ? { x: 0, y: 0 } : { x: -310, y: 0 });
    graph.evidence.forEach((record, index) => {
      if (layout === 'orbit') {
        const angle = -Math.PI / 2 + index * 2 * Math.PI / Math.max(graph.evidence.length, 1);
        positions.set(record.key, { x: Math.cos(angle) * 260, y: Math.sin(angle) * 260 });
      } else positions.set(record.key, { x: 0, y: (index - (graph.evidence.length - 1) / 2) * 58 });
    });
    graph.visibleGroups.forEach((name, index) => {
      if (layout === 'orbit') {
        const angle = -Math.PI / 2 + (index + 0.5) * 2 * Math.PI / Math.max(graph.visibleGroups.length, 1);
        positions.set(`group:${name}`, { x: Math.cos(angle) * 510, y: Math.sin(angle) * 510 });
      } else positions.set(`group:${name}`, { x: 330, y: (index - (graph.visibleGroups.length - 1) / 2) * 62 });
    });
    return positions;
  }
  function spotlightMap() {
    if (!mapCy) return;
    mapCy.elements().removeClass('is-muted is-linked is-current is-concealed');
    const active = mapCy.getElementById(mapHover || selectedKey);
    if (!active.length) return;
    const neighborhood = active.closedNeighborhood();
    if (currentMap?.links.length > 40 && !mapAllLinks) {
      const focusEdges = mapCy.edges().filter((edge) => edge.source().data('focus') === 1);
      mapCy.edges().difference(focusEdges.union(active.connectedEdges())).addClass('is-concealed');
    }
    if (mapHover) mapCy.elements().difference(neighborhood).addClass('is-muted');
    neighborhood.addClass('is-linked');
    active.addClass('is-current');
  }
  function applyMapLayout(graph) {
    if (!mapCy) return;
    const positions = mapPositions(graph, state.layout);
    mapCy.layout({ name: 'preset', positions: (node) => positions.get(node.id()) || node.position(),
      animate: !window.matchMedia?.('(prefers-reduced-motion: reduce)').matches,
      animationDuration: 380, fit: true, padding: 46 }).run();
    renderedMapLayout = state.layout;
  }
  function renderCanvasMap(graph) {
    const host = $('[data-map-canvas]');
    if (typeof window.cytoscape !== 'function' || !document.createElement('canvas').getContext) {
      host.hidden = true; $('.group-map-scroll').hidden = false; return false;
    }
    const sceneKey = JSON.stringify([graph.group, graph.evidence.map((r) => r.key), graph.visibleGroups, graph.links]);
    host.hidden = false;
    $('.group-map-scroll').hidden = true;
    if (mapCy && mapSceneKey === sceneKey) {
      if (renderedMapLayout !== state.layout) applyMapLayout(graph);
      spotlightMap(); return true;
    }
    mapCy?.destroy(); mapCy = null; mapSceneKey = ''; mapHover = '';
    const positions = mapPositions(graph, state.layout);
    const groupNode = (name, focus) => ({ data: { id: `group:${name}`, kind: 'group', name, label: name, focus: focus ? 1 : 0 }, position: positions.get(`group:${name}`) });
    const elements = [groupNode(graph.group, true), ...graph.visibleGroups.map((name) => groupNode(name, false)),
      ...graph.evidence.map((record) => ({ data: { id: record.key, kind: 'evidence', key: record.key, label: record.value,
        shortLabel: record.value.length > 27 ? `${record.value.slice(0, 24)}…` : record.value,
        matched: record.matched ? 1 : 0 }, position: positions.get(record.key) })),
      ...graph.links.map((edge, index) => ({ data: { id: `link:${index}`, source: `group:${edge.group}`, target: edge.evidence } }))];
    try {
      mapCy = window.cytoscape({ container: host, elements, layout: { name: 'preset', fit: true, padding: 46 },
        minZoom: .3, maxZoom: 3, wheelSensitivity: .16, boxSelectionEnabled: false,
        style: [
          { selector: 'node', style: { 'label': 'data(label)', 'font-family': 'system-ui, sans-serif', 'font-size': 14,
            'font-weight': 600, 'color': '#f4f7f0', 'text-valign': 'center', 'text-halign': 'center',
            'text-wrap': 'ellipsis', 'text-max-width': 155, 'text-outline-width': 0,
            'shape': 'round-rectangle', 'width': 170, 'height': 44, 'border-width': 2,
            'background-color': '#26352f', 'border-color': '#9cb19a' } },
          { selector: 'node[kind = "group"]', style: { 'width': 154, 'height': 52, 'background-color': '#3c3030', 'border-color': '#d8ad86' } },
          { selector: 'node[focus = 1]', style: { 'background-color': '#75513b', 'border-color': '#ffce9c', 'border-width': 3 } },
          { selector: 'node[kind = "evidence"]', style: { 'label': 'data(shortLabel)', 'background-color': '#27362f', 'border-color': '#a9b6a3' } },
          { selector: 'node[matched = 1]', style: { 'background-color': '#134c4a', 'border-color': '#5ce1cd' } },
          { selector: 'edge', style: { 'curve-style': 'bezier', 'line-color': '#8ca59a', 'width': 1.8, 'opacity': .32 } },
          { selector: 'edge.is-concealed', style: { 'opacity': 0 } },
          { selector: 'edge.is-linked', style: { 'line-color': '#91ecdb', 'width': 3, 'opacity': .88 } },
          { selector: 'node.is-linked', style: { 'opacity': 1 } },
          { selector: 'node.is-current', style: { 'border-color': '#fff0bf', 'border-width': 4, 'shadow-blur': 18,
            'shadow-color': '#eac07e', 'shadow-opacity': .55 } },
          { selector: '.is-muted', style: { 'opacity': .12 } },
        ] });
      mapSceneKey = sceneKey;
      renderedMapLayout = state.layout;
      mapCy.on('mouseover', 'node', (event) => { mapHover = event.target.id(); spotlightMap(); host.title = event.target.data('label'); });
      mapCy.on('mouseout', 'node', () => { mapHover = ''; spotlightMap(); host.removeAttribute('title'); });
      mapCy.on('tap', 'node', (event) => {
        const node = event.target.data();
        if (node.kind === 'evidence') selectEvidence(node.key);
        else if (node.name !== state.group) selectGroup(node.name);
      });
      if (window.matchMedia?.('(max-width: 700px)').matches && mapCy.zoom() < .72) {
        mapCy.zoom(.8);
        mapCy.center(mapCy.getElementById(selectedKey));
      }
      spotlightMap();
      return true;
    } catch (error) {
      mapCy?.destroy(); mapCy = null; mapSceneKey = '';
      host.hidden = true; $('.group-map-scroll').hidden = false;
      return false;
    }
  }
  function renderFallbackMap(graph) {
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
  }
  function renderMapRelationships(graph) {
    const host = $('[data-map-relationships]'); host.replaceChildren();
    graph.evidence.forEach((record) => {
      const row = el('div', '', 'group-map-relationship-row');
      row.appendChild(button(record.value, () => selectEvidence(record.key), 'group-link-button'));
      const shown = record.groups.filter((name) => name === graph.group || graph.visibleGroups.includes(name));
      row.appendChild(el('span', `${record.matched ? 'In SwiftIOC' : 'Research candidate'} · Reported for ${shown.join(', ')}${record.groups.length > shown.length ? ` · +${record.groups.length - shown.length} outside this map` : ''}`, 'group-small'));
      host.appendChild(row);
    });
  }
  function updateMapSearch() {
    const input = $('[data-map-search]'), host = $('[data-map-results]');
    const term = input.value.trim().toLowerCase().replaceAll('[.]', '.');
    host.replaceChildren(); host.hidden = !term;
    if (!term || !model || state.view !== 'graph') return;
    const matches = core.filter(model, { group: state.group, kind: state.mapKind })
      .filter((record) => record.value.toLowerCase().replaceAll('[.]', '.').includes(term)).slice(0, 8);
    matches.forEach((record) => host.appendChild(button(`${record.value} · ${record.matched ? 'In SwiftIOC' : 'Research candidate'}`,
      () => { input.value = ''; host.hidden = true; selectEvidence(record.key); }, 'group-map-result')));
    if (!matches.length) host.appendChild(el('p', 'No matching record for this group and evidence type.', 'group-small'));
  }
  function renderGraph() {
    if (!state.group) state.group = [...model.groups.keys()].sort((a, b) => core.filter(model, { group: b, kind: state.mapKind }).length - core.filter(model, { group: a, kind: state.mapKind }).length)[0] || '';
    const graph = core.graph(model, state.group, state.mapKind, selectedKey); currentMap = graph; selectedKey = graph.selected?.key || '';
    $('[data-map-kind]').value = state.mapKind;
    $('[data-map-layout]').value = state.layout;
    const choice = $('[data-map-evidence]'); choice.replaceChildren();
    graph.evidence.forEach((r) => { const option = el('option', r.value); option.value = r.key; choice.appendChild(option); }); choice.value = selectedKey; choice.disabled = !graph.selected;
    const denseMap = graph.links.length > 40;
    $('[data-map-all-links-wrap]').hidden = !denseMap;
    $('[data-map-all-links]').checked = mapAllLinks;
    $('[data-map-status]').textContent = `Showing ${graph.evidence.length} of ${graph.total} ${labels[state.mapKind]}, ${graph.visibleGroups.length} of ${graph.visibleGroupsTotal} other groups, and ${graph.links.length} direct reported links for ${state.group}. ${graph.total > 12 ? 'Find a specific record above or use the evidence table for all records. ' : ''}${denseMap && !mapAllLinks ? 'To reduce clutter, only the focus-group and selected-record lines are shown; hover a node or choose All links to reveal more. ' : ''}Layout and proximity do not imply collaboration.`;
    if (!renderCanvasMap(graph)) renderFallbackMap(graph);
    renderMapRelationships(graph);
    updateMapSearch();
    const inspector = $('[data-map-inspector]'); inspector.replaceChildren();
    if (graph.selected) {
      inspector.append(el('span', 'Selected evidence', 'group-map-inspector-kicker'), el('strong', graph.selected.value),
        el('p', `${graph.selected.matched ? 'Exact match in the retained SwiftIOC feed' : 'Research candidate'} · ${graph.selected.groups.length} reported group${graph.selected.groups.length === 1 ? '' : 's'}. A shared record is not proof of collaboration or current use.`, 'group-small'),
        groupLinks(graph.selected.groups), investigate(graph.selected));
      inspector.appendChild(evidenceReceipt(graph.selected));
    } else inspector.appendChild(el('p', 'No evidence of this type in the snapshot. Choose another evidence type or group.'));
    $('[data-map-export]').disabled = !graph.selected;
  }
  function render() {
    if (state.view === 'graph' && !state.group && model) {
      state.group = [...model.groups.keys()].sort((a, b) => core.filter(model, { group: b, kind: state.mapKind }).length - core.filter(model, { group: a, kind: state.mapKind }).length)[0] || '';
    }
    $('[data-group-choice]').value = state.group;
    const active = $('[data-active-group]'); active.replaceChildren();
    active.append(el('h2', state.group || 'All groups'), el('span', 'Reported associations · current use is not established', 'group-small'));
    document.querySelectorAll('[data-view]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === state.view)));
    document.querySelectorAll('[data-panel]').forEach((panel) => { panel.hidden = panel.dataset.panel !== (['iocs', 'cves', 'ttps'].includes(state.view) ? 'records' : state.view); });
    if (state.view !== 'graph' && mapCy) { mapCy.destroy(); mapCy = null; mapSceneKey = ''; }
    if (state.view === 'graph') renderGraph();
    else if (state.view === 'overview') renderOverview();
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
    $('[data-map-kind]').addEventListener('change', (event) => { $('[data-map-search]').value = ''; navigate({ mapKind: event.target.value }); });
    $('[data-map-search]').addEventListener('input', updateMapSearch);
    $('[data-map-evidence]').addEventListener('change', (event) => selectEvidence(event.target.value));
    $('[data-map-all-links]').addEventListener('change', (event) => { mapAllLinks = event.target.checked; renderGraph(); });
    $('[data-map-layout]').addEventListener('change', (event) => {
      state.layout = event.target.value === 'orbit' ? 'orbit' : 'lanes';
      history.replaceState(null, '', `#${new URLSearchParams(Object.entries(state).filter(([, value]) => value))}`);
      if (mapCy && currentMap) applyMapLayout(currentMap);
      else renderGraph();
    });
    $('[data-map-fit]').addEventListener('click', () => mapCy?.fit(undefined, 46));
    for (const [selector, factor] of [['[data-map-zoom-in]', 1.25], ['[data-map-zoom-out]', .8]]) {
      $(selector).addEventListener('click', () => {
        if (!mapCy) return;
        const host = $('[data-map-canvas]');
        mapCy.zoom({ level: Math.max(.3, Math.min(3, mapCy.zoom() * factor)),
          renderedPosition: { x: host.clientWidth / 2, y: host.clientHeight / 2 } });
      });
    }
    $('[data-map-export]').addEventListener('click', () => {
      if (!currentMap) return;
      const nodes = [{ id: `group:${currentMap.group}`, type: 'group', value: currentMap.group },
        ...currentMap.evidence.map((r) => ({ id: r.key, type: r.type, value: r.value, in_swiftioc: r.matched })),
        ...currentMap.visibleGroups.map((name) => ({ id: `group:${name}`, type: 'group', value: name }))];
      const edges = currentMap.links.map((edge) => ({ from: `group:${edge.group}`, to: edge.evidence,
        relationship: edge.relationship }));
      const blob = new Blob([JSON.stringify({ schema_version: 1, source: 'ransomware.live', generated_at: model.generatedAt,
        scope: 'displayed-evidence-map', selected_evidence: currentMap.selected?.key || null,
        limits: { evidence: 12, other_groups: 10 },
        caveat: 'These are reported group-to-record associations. Layout, proximity and shared records do not establish current use, local exposure, collaboration or campaign attribution.',
        nodes, edges }, null, 2)], { type: 'application/json' });
      const href = URL.createObjectURL(blob); const a = link('', href); a.download = 'swiftioc-group-map.json'; a.click(); setTimeout(() => URL.revokeObjectURL(href), 1000);
    });
  }).catch(() => { $('[data-page-status]').textContent = 'Group evidence could not be loaded. Reload this page to try again, or return to the intelligence desk.'; });
})();
