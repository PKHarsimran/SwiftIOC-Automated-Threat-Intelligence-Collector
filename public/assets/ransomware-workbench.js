(() => {
  'use strict';
  const $ = (selector) => document.querySelector(selector);
  const el = (tag, text = '', className = '') => { const node = document.createElement(tag); node.textContent = text; if (className) node.className = className; return node; };
  const button = (text, action, className = 'group-link-button') => { const node = el('button', text, className); node.type = 'button'; node.addEventListener('click', action); return node; };
  const link = (text, href) => { const node = el('a', text); node.href = href; return node; };
  const workbench = window.SwiftIOCRansomwareWorkbench;
  const groupCore = window.SwiftIOCGroupCore;
  let model; let context; let guidance; let state = { tab: 'radar', group: '' };
  const telemetry = ['endpoint', 'identity', 'network', 'dns', 'proxy', 'email', 'cloud'];
  const readLocal = (key, fallback) => { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } };
  const writeLocal = (key, value) => { try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; } };
  const decisionKey = 'swiftioc.candidateDecisions.v1';
  let candidateDecisions = workbench.normalizeDecisions(readLocal(decisionKey, {}));
  let cveSignalsPromise = null;
  let priorityLimit = 30;
  const selectedTelemetry = () => [...document.querySelectorAll('[data-telemetry] input:checked')].map((input) => input.value);
  const cveSignals = () => {
    if (!cveSignalsPromise) cveSignalsPromise = fetch('cve_signals.json', { cache: 'no-cache' })
      .then((response) => response.ok ? response.json() : null).catch(() => null);
    return cveSignalsPromise;
  };
  function navigate(change, replace = false) {
    state = { ...state, ...change }; render();
    const params = new URLSearchParams(Object.entries(state).filter(([, value]) => value));
    history[replace ? 'replaceState' : 'pushState'](null, '', `#${params}`);
  }
  function readLocation() {
    const params = new URLSearchParams(location.hash.slice(1));
    const tab = ['radar', 'priorities', 'compare', 'coverage', 'triage', 'exposure', 'watchlist'].includes(params.get('tab')) ? params.get('tab') : 'radar';
    const group = model.groups.has(params.get('group')) ? params.get('group') : '';
    state = { tab, group }; render();
  }
  function bars(host, rows, empty = 'No aggregate data available yet.') {
    host.replaceChildren();
    if (!rows?.length) { host.appendChild(el('p', empty, 'group-small')); return; }
    const wrap = el('div', '', 'metric-bars'); const max = Math.max(...rows.map((row) => row.count), 1);
    rows.slice(0, 10).forEach((row) => {
      const item = el('div', '', 'metric-bar'); item.title = `${row.name || row.date}: ${row.count}`;
      const track = el('div', '', 'metric-bar-track'); const fill = el('i'); fill.style.width = `${Math.max(3, row.count / max * 100)}%`; track.appendChild(fill);
      item.append(el('span', row.name || row.date), track, el('strong', String(row.count))); wrap.appendChild(item);
    }); host.appendChild(wrap);
  }
  function renderContext() {
    $('[data-group]').value = state.group;
    const host = $('[data-context-summary]'); host.replaceChildren();
    if (!state.group) {
      host.append(el('span', `${model.groups.size} groups`), el('span', `${model.records.filter((r) => r.kind === 'iocs').length.toLocaleString()} reported IOCs`), el('span', `${model.records.filter((r) => r.kind === 'cves').length} CVEs`));
      return;
    }
    const signals = workbench.groupSignals(model, state.group);
    host.append(el('span', `${signals.iocs} IOCs`), el('span', `${signals.cves} CVEs`), el('span', `${signals.techniques} techniques`), el('span', `${signals.changes30d} changes / 30d`), el('span', `${signals.churn}% IOC churn`));
    for (const [kind, label] of [['yara', 'YARA'], ['ransom_notes', 'ransom notes'], ['negotiations', 'negotiations']]) {
      const item = context?.available?.[kind]?.find((row) => row.group.toLowerCase() === state.group.toLowerCase());
      if (item) host.appendChild(el('span', `${item.count} ${label}`));
    }
  }
  function renderRadar() {
    const timeline = $('[data-activity-chart]'); timeline.replaceChildren();
    timeline.appendChild(el('h3', 'Recent victim reporting'));
    const victims = el('div'); timeline.appendChild(victims); bars(victims, context?.activity?.by_day || [], 'Aggregate activity will appear after the next provider refresh.');
    timeline.appendChild(el('h3', 'Recent cyberattack press reporting'));
    const press = el('div'); timeline.appendChild(press); bars(press, (context?.activity?.press_by_day || []).slice(-10), 'No aggregate press timeline is available yet.');
    bars($('[data-activity-groups]'), context?.activity?.groups || []);
    const combined = [...(context?.activity?.sectors || []).slice(0, 5).map((row) => ({ ...row, name: `Sector · ${row.name}` })), ...(context?.activity?.countries || []).slice(0, 5).map((row) => ({ ...row, name: `Country · ${row.name}` }))];
    bars($('[data-activity-context]'), combined);
    const anomalies = workbench.anomalies(model); const host = $('[data-anomalies]'); host.replaceChildren();
    if (!anomalies.length) host.appendChild(el('p', model.history?.events?.length ? 'No evidence-change bursts meet the current threshold.' : 'The local baseline is still accumulating. No burst claim can be made yet.', 'group-small'));
    anomalies.slice(0, 8).forEach((item) => { const row = el('div', '', 'group-short-row'); row.append(button(item.group, () => navigate({ group: item.group, tab: 'priorities' })), el('span', `${item.count} changes / 7d${item.ratio ? ` · ${item.ratio}× baseline` : ' · no earlier baseline'}`, 'group-small')); host.appendChild(row); });
  }
  function renderPriorities() {
    const kind = $('[data-priority-kind]').value, observable = $('[data-priority-observable]').value;
    const reviewFilter = $('[data-priority-review]'); reviewFilter.disabled = kind !== 'candidates';
    const queue = workbench.priorityQueue(model, { group: state.group, kind, observable, review: reviewFilter.value, decisions: candidateDecisions });
    const ranked = queue.records.map((record) => ({ record, ...workbench.priority(record, model), quality: workbench.quality(record, model) }))
      .sort((a, b) => b.score - a.score || b.record.groups.length - a.record.groups.length || a.record.value.localeCompare(b.record.value));
    const host = $('[data-priorities]'); host.replaceChildren();
    const coverage = workbench.coverageSummary(model, state.group);
    const decisions = queue.decisionCounts;
    $('[data-priority-summary]').textContent = `${ranked.length} in this view · ${coverage.candidates} IOC candidates in ${state.group ? state.group : 'all groups'} (${decisions.pending} awaiting review, ${decisions.observed} locally observed, ${decisions.dismissed} dismissed) · ${coverage.feedIocMatches} exact retained-feed IOC matches · ${coverage.feedCveMatches}/${coverage.reportedCves} reported CVEs retained.${!state.group && coverage.groupsWithoutIocCollection !== null ? ` ${coverage.groupsWithoutIocCollection} groups have no IOC collection available.` : ''} Unmatched does not mean safe or malicious.`;
    $('[data-priority-more]').hidden = ranked.length <= priorityLimit;
    $('[data-priority-more]').textContent = `Show more (${Math.min(30, ranked.length - priorityLimit)} of ${ranked.length - priorityLimit} remaining)`;
    if (!ranked.length) host.appendChild(el('p', kind === 'candidates' && reviewFilter.value === 'pending'
      ? 'No candidates await review in this scope. Change the status filter to see local decisions, or choose another group or IOC type.'
      : 'No evidence matches these filters.', 'group-small'));
    ranked.slice(0, priorityLimit).forEach((item) => {
      const card = el('article', '', 'priority-card'); const body = el('div'); body.append(el('h3', item.record.value), el('p', `${item.record.type} · ${item.record.groups.slice(0, 3).join(', ')}${item.record.groups.length > 3 ? ` +${item.record.groups.length - 3}` : ''} · ${item.record.matched ? 'in SwiftIOC' : 'research candidate'}`, 'group-small'));
      let receiptText = '';
      if (item.record.kind === 'iocs') {
        const receipt = groupCore.receipt(model, item.record, item.record.groups[0]);
        receiptText = receipt ? `Present in provider snapshots from ${receipt.first_observed || 'an unknown first date'} to ${receipt.last_observed || 'an unknown last date'}. These are collection receipts, not dated attack sightings.` : 'No local first/last collection receipt available.';
      }
      const details = el('details'); details.append(el('summary', 'Why this score'), el('ul'));
      item.reasons.forEach((reason) => details.lastChild.appendChild(el('li', reason))); body.appendChild(details);
      const quality = el('details'); quality.append(el('summary', 'Evidence-quality receipt'), el('p', item.quality.meaning, 'group-small'), el('ul'));
      item.quality.reasons.forEach((reason) => quality.lastChild.appendChild(el('li', reason))); body.appendChild(quality);
      if (receiptText) quality.appendChild(el('p', receiptText, 'group-small'));
      const actions = el('div'); actions.appendChild(button('Triage evidence', () => { $('[data-triage-input]').value = item.record.value; navigate({ tab: 'triage' }); renderTriage(workbench.triage(model, item.record.value)); }));
      actions.appendChild(button('Export case', async () => {
        try {
          const signals = item.record.kind === 'cves' ? await cveSignals() : null;
          const pack = workbench.casePack(model, item.record, {
            decision: candidateDecisions[item.record.key], signal: signals?.items?.[item.record.value],
            signalSnapshotAt: signals?.generated_at || null, buildSpl: window.SwiftIOCCore?.buildSplQuery,
          });
          download(pack, `swiftioc-case-${item.record.value.replace(/[^a-z0-9.-]/gi, '_').slice(0, 80)}.json`);
          $('[data-status]').textContent = 'Evidence case exported locally. It does not change the public feed or prove attribution.';
        } catch (error) { $('[data-status]').textContent = `Case export unavailable: ${error.message}`; }
      }));
      if (item.record.kind === 'iocs' && !item.record.matched) {
        const key = item.record.key;
        const local = candidateDecisions[key];
        const recorded = local?.at && Number.isFinite(Date.parse(local.at)) ? ` (${new Date(local.at).toLocaleString()})` : '';
        body.appendChild(el('p', local?.status === 'observed' ? `Your local decision${recorded}: observed in your telemetry. This does not verify actor attribution or alter the public feed.`
          : local?.status === 'dismissed' ? `Your local decision${recorded}: dismissed for this investigation.` : 'Suggested next step: hunt the exact value in your telemetry, then record what you actually observed.', 'group-small'));
        actions.appendChild(button('Observed in my logs', () => {
          candidateDecisions[key] = { status: 'observed', at: new Date().toISOString() };
          if (!writeLocal(decisionKey, candidateDecisions)) $('[data-status]').textContent = 'Browser storage unavailable; local decision lasts only this session.';
          else $('[data-status]').textContent = 'Local observation recorded. Use Candidate status to review or undo it; this does not verify group attribution.';
          priorityLimit = 30;
          renderPriorities();
        }));
        actions.appendChild(button('Dismiss locally', () => {
          candidateDecisions[key] = { status: 'dismissed', at: new Date().toISOString() };
          if (!writeLocal(decisionKey, candidateDecisions)) $('[data-status]').textContent = 'Browser storage unavailable; local decision lasts only this session.';
          else $('[data-status]').textContent = 'Local dismissal recorded. Use Candidate status to review or undo it.';
          priorityLimit = 30;
          renderPriorities();
        }));
        if (local) actions.appendChild(button('Clear decision', () => { delete candidateDecisions[key]; writeLocal(decisionKey, candidateDecisions); renderPriorities(); }));
      }
      card.append(el('div', String(item.score), 'priority-score'), body, actions); host.appendChild(card);
    });
  }
  function renderCompare() {
    const selector = $('[data-compare]');
    if (!state.group) { $('[data-comparison]').replaceChildren(el('p', 'Select a focus group to compare its reported evidence.')); selector.disabled = true; return; }
    selector.disabled = false; const matches = workbench.similarities(model, state.group); const requested = selector.value;
    const chosen = matches.find((item) => item.group === requested) || matches[0];
    selector.replaceChildren(el('option', 'Best match')); selector.firstChild.value = '';
    matches.slice(0, 50).forEach((item) => { const option = el('option', `${item.group} · ${item.score}%`); option.value = item.group; selector.appendChild(option); });
    if (requested && matches.some((item) => item.group === requested)) selector.value = requested;
    const host = $('[data-comparison]'); host.replaceChildren();
    if (!chosen) { host.appendChild(el('p', 'No overlapping reported evidence was found.')); return; }
    const score = el('div', '', 'compare-score'); score.append(el('strong', `${chosen.score}%`), el('p', `${state.group} and ${chosen.group} share reported evidence. This score is descriptive, not an attribution confidence.`)); host.appendChild(score);
    const grid = el('div', '', 'dna-grid'); [['ATT&CK techniques', chosen.shared.ttps], ['CVEs', chosen.shared.cves], ['IOCs', chosen.shared.iocs]].forEach(([label, value]) => { const card = el('div', label, 'dna-card'); card.appendChild(el('strong', String(value))); grid.appendChild(card); }); host.appendChild(grid);
    const signals = workbench.groupSignals(model, state.group); const other = workbench.groupSignals(model, chosen.group);
    host.appendChild(el('p', `30-day evidence changes: ${state.group} ${signals.changes30d}, ${chosen.group} ${other.changes30d}. IOC churn: ${signals.churn}% vs ${other.churn}%.`, 'group-small'));
  }
  function download(value, filename) {
    const href = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })); const anchor = link('', href); anchor.download = filename; anchor.click(); setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  function renderCasePreview(saved) {
    const host = $('[data-case-preview]'); host.replaceChildren();
    const change = workbench.compareCase(saved, model), record = saved.record;
    const box = el('div', '', 'result-box'); box.append(el('h3', `${record.value} · ${record.type}`),
      el('p', `Saved ${new Date(saved.exported_at).toLocaleString()} from provider snapshot ${new Date(saved.group_snapshot_at).toLocaleString()}. ${record.groups.length} reported group association${record.groups.length === 1 ? '' : 's'} and ${saved.receipts?.length || 0} collection receipts in the file.`, 'group-small'),
      el('p', change.present ? (change.snapshotSame ? 'Same provider snapshot is loaded.' : `Current snapshot differs: ${change.addedGroups.length} group links added, ${change.removedGroups.length} removed${change.feedMatchChanged ? ', and retained-feed match changed' : ''}. Review the evidence before reusing the case.`) : 'This exact evidence record is absent from the current provider snapshot. Absence is not a negative finding.', 'group-small'));
    if (saved.analyst_decision?.status) box.appendChild(el('p', `Saved local decision: ${saved.analyst_decision.status} at ${saved.analyst_decision.at}. This is user supplied, not group attribution.`, 'group-small'));
    if (record.kind === 'cves' && /^CVE-\d{4}-\d{4,19}$/.test(record.value)) {
      const anchor = link('Open official CVE record ↗', `https://www.cve.org/CVERecord?id=${record.value}`); anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; box.appendChild(anchor);
    }
    host.appendChild(box);
  }
  function renderCoverage() {
    const host = $('[data-coverage]'); host.replaceChildren(); const summary = $('[data-coverage-summary]'); summary.replaceChildren();
    if (!state.group) { summary.appendChild(el('p', 'Select a focus group to map its reported techniques to your telemetry.')); return; }
    const rows = workbench.coverage(model, state.group, selectedTelemetry()); const counts = { searchable: 0, gap: 0, unmapped: 0 }; rows.forEach((row) => counts[row.status]++);
    summary.append(el('p', `${counts.searchable} searchable · ${counts.gap} telemetry gaps · ${counts.unmapped} require manual mapping`, 'group-small'), button('Download multi-format response pack', () => {
      try { download(workbench.responsePack(model, state.group, '*', '-7d', window.SwiftIOCCore), `swiftioc-response-${state.group.replace(/[^a-z0-9_-]/gi, '_')}.json`); }
      catch (error) { $('[data-status]').textContent = error.message; }
    }, 'button'));
    rows.forEach((row) => {
      const card = el('div', '', 'coverage-card'); card.dataset.status = row.status;
      card.append(el('strong', row.technique), el('p', row.status === 'unmapped' ? 'Manual telemetry mapping required' : `${row.status === 'searchable' ? 'Potentially searchable' : 'Broad telemetry gap'} · ${row.required.join(', ')}`, 'group-small'));
      const entry = guidance?.techniques?.[row.technique];
      const source = link('Open MITRE technique and detection guidance ↗', entry?.technique_url || `https://attack.mitre.org/techniques/${row.technique.replace('.', '/')}/`);
      source.target = '_blank'; source.rel = 'noopener noreferrer'; card.appendChild(source);
      if (entry?.strategies?.length) {
        const details = el('details'); details.appendChild(el('summary', `${entry.strategies.length} MITRE detection strategies`));
        entry.strategies.forEach((strategy) => {
          const section = el('div'); const anchor = link(`${strategy.id} · ${strategy.name} ↗`, strategy.url); anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; section.appendChild(anchor);
          const analytics = strategy.analytics || [];
          if (analytics.length) section.appendChild(el('p', analytics.map((item) => `${item.id}: ${(item.platforms || []).join('/') || 'platform unspecified'} · ${(item.log_sources || []).join(', ') || 'check strategy for required logs'}`).join(' | '), 'group-small'));
          details.appendChild(section);
        }); card.appendChild(details);
      } else card.appendChild(el('p', 'No published strategy mapped in this cached guidance; inspect MITRE manually. This is not a detection verdict.', 'group-small'));
      host.appendChild(card);
    });
  }
  function renderTriage(result = null) {
    const host = $('[data-triage-result]'); if (result === null) return;
    host.replaceChildren(); const box = el('div', '', 'result-box');
    if (!result) box.appendChild(el('p', 'No exact match. Refang the value if needed and verify its type. Partial matches are intentionally disabled.'));
    else if (result.kind === 'group') {
      box.append(el('h3', result.group), el('p', `${result.signals.iocs} IOCs · ${result.signals.cves} CVEs · ${result.signals.techniques} techniques · ${result.signals.churn}% IOC churn`, 'group-small'), button('Use as focus group', () => navigate({ group: result.group, tab: 'priorities' })));
    } else result.records.forEach((record) => { const item = workbench.priority(record, model); box.append(el('h3', record.value), el('p', `${record.type} · priority ${item.score}/100 · ${record.groups.join(', ')}`, 'group-small'), link('Open evidence map →', `groups.html#view=graph&group=${encodeURIComponent(record.groups[0] || '')}&mapKind=${record.kind}&evidence=${encodeURIComponent(record.key)}`)); });
    host.appendChild(box);
  }
  function renderExposure(result = null) {
    if (result === null) return; const host = $('[data-exposure-result]'); host.replaceChildren(); const box = el('div', '', 'result-box');
    if (!result.found.length) box.appendChild(el('p', 'No exact ransomware association matched the supplied values. This does not prove those assets are safe.'));
    result.found.forEach((item) => { const row = el('div', '', 'group-short-row'); row.append(el('strong', item.token), el('span', item.result.kind === 'group' ? 'Reported group' : `${item.result.records.length} exact evidence match(es)`, 'group-small')); box.appendChild(row); });
    if (result.unknown.length) box.appendChild(el('p', `${result.unknown.length} value(s) had no exact match. Product names and versions are not guessed; use CVE IDs from your authoritative asset scanner.`, 'group-small')); host.appendChild(box);
  }
  function renderWatchlist(message = '') {
    const watch = Object.fromEntries([...document.querySelectorAll('[data-watch]')].map((node) => [node.dataset.watch, node.value])); const result = workbench.watchMatches(model, context, watch);
    const host = $('[data-watch-results]'); host.replaceChildren(); const box = el('div', '', 'result-box');
    if (message) box.appendChild(el('p', message));
    box.append(el('h3', 'Current matches'), el('p', `${result.groups.length} groups · ${result.evidence.length} exact evidence records · ${result.countries.length} countries · ${result.sectors.length} sectors`, 'group-small'));
    [...result.groups, ...result.evidence.map((r) => r.value), ...result.countries.map((r) => `${r.name} (${r.count})`), ...result.sectors.map((r) => `${r.name} (${r.count})`)].slice(0, 30).forEach((value) => box.appendChild(el('span', value, 'group-evidence-badge'))); host.appendChild(box);
  }
  function render() {
    document.querySelectorAll('[data-tab]').forEach((node) => node.setAttribute('aria-pressed', String(node.dataset.tab === state.tab)));
    document.querySelectorAll('[data-panel]').forEach((node) => { node.hidden = node.dataset.panel !== state.tab; });
    renderContext();
    if (state.tab === 'radar') renderRadar();
    if (state.tab === 'priorities') renderPriorities();
    if (state.tab === 'compare') renderCompare();
    if (state.tab === 'coverage') renderCoverage();
    if (state.tab === 'watchlist') renderWatchlist();
  }
  Promise.all([
    fetch('group_evidence.json', { cache: 'no-cache' }).then((response) => { if (!response.ok) throw new Error('Evidence unavailable'); return response.json(); }),
    fetch('ransomware_context.json', { cache: 'no-cache' }).then((response) => response.ok ? response.json() : null).catch(() => null),
    fetch('attack_guidance.json', { cache: 'no-cache' }).then((response) => response.ok ? response.json() : null).catch(() => null),
  ]).then(([evidence, activity, detectionGuidance]) => {
    model = groupCore.build(evidence); context = activity;
    guidance = detectionGuidance?.schema_version === 1 && Date.parse(detectionGuidance.generated_at) <= Date.now() ? detectionGuidance : null;
    const contextReady = context && Date.parse(context.generated_at) >= Date.parse('2025-01-01T00:00:00Z');
    $('[data-status]').textContent = `Evidence ${new Date(model.generatedAt).toLocaleString()} · ${contextReady ? `aggregate activity ${new Date(context.generated_at).toLocaleString()}` : 'activity aggregate pending first refresh'} · browser tools make no API calls.`;
    const selector = $('[data-group]'); [...model.groups.keys()].sort().forEach((name) => { const option = el('option', name); option.value = name; selector.appendChild(option); });
    const savedTelemetry = new Set(readLocal('swiftioc.telemetry', [])); const picker = $('[data-telemetry]');
    telemetry.forEach((name) => { const label = el('label'); const input = document.createElement('input'); input.type = 'checkbox'; input.value = name; input.checked = savedTelemetry.has(name); input.addEventListener('change', () => { writeLocal('swiftioc.telemetry', selectedTelemetry()); renderCoverage(); }); label.append(input, document.createTextNode(name)); picker.appendChild(label); });
    const savedWatch = readLocal('swiftioc.ransomwareWatch', {}); document.querySelectorAll('[data-watch]').forEach((node) => { node.value = savedWatch[node.dataset.watch] || ''; });
    $('[data-app]').hidden = false; readLocation();
    window.addEventListener('popstate', readLocation); window.addEventListener('hashchange', readLocation);
    document.querySelectorAll('[data-tab]').forEach((node) => node.addEventListener('click', () => navigate({ tab: node.dataset.tab })));
    selector.addEventListener('change', (event) => navigate({ group: event.target.value }));
    $('[data-priority-kind]').addEventListener('change', () => { priorityLimit = 30; renderPriorities(); });
    $('[data-priority-observable]').addEventListener('change', () => { priorityLimit = 30; renderPriorities(); });
    $('[data-priority-review]').addEventListener('change', () => { priorityLimit = 30; renderPriorities(); });
    $('[data-compare]').addEventListener('change', renderCompare);
    $('[data-priority-more]').addEventListener('click', () => { priorityLimit += 30; renderPriorities(); });
    $('[data-candidate-export]').addEventListener('click', () => download({ schema_version: 1, source: 'browser-local analyst decisions',
      group_snapshot_at: model.generatedAt, exported_at: new Date().toISOString(), decisions: candidateDecisions,
      limitation: 'A local observation or dismissal is user supplied, not confirmation of ransomware-group attribution or a published feed update.' }, 'swiftioc-candidate-decisions.json'));
    $('[data-case-file]').addEventListener('change', async (event) => {
      const file = event.target.files?.[0]; if (!file) return;
      try {
        if (file.size > 500_000) throw new Error('Case file is too large (500 KB limit).');
        renderCasePreview(workbench.parseCase(JSON.parse(await file.text())));
      } catch (error) { $('[data-case-preview]').replaceChildren(el('p', `Cannot open case: ${error.message}`, 'group-small')); }
      finally { event.target.value = ''; }
    });
    $('[data-quick-plan]').addEventListener('click', () => { const group = state.group || [...model.groups.keys()].sort((a, b) => model.byGroup.get(b).length - model.byGroup.get(a).length)[0]; navigate({ group, tab: 'coverage' }); });
    $('[data-triage-form]').addEventListener('submit', (event) => { event.preventDefault(); renderTriage(workbench.triage(model, $('[data-triage-input]').value)); });
    $('[data-exposure-check]').addEventListener('click', () => renderExposure(workbench.exposure(model, $('[data-exposure-input]').value)));
    $('[data-watch-save]').addEventListener('click', () => { const value = Object.fromEntries([...document.querySelectorAll('[data-watch]')].map((node) => [node.dataset.watch, node.value])); renderWatchlist(writeLocal('swiftioc.ransomwareWatch', value) ? 'Saved locally in this browser.' : 'Browser storage is unavailable; values remain only until this page closes.'); });
    $('[data-watch-clear]').addEventListener('click', () => { document.querySelectorAll('[data-watch]').forEach((node) => { node.value = ''; }); try { localStorage.removeItem('swiftioc.ransomwareWatch'); } catch {} renderWatchlist('Local watchlist cleared.'); });
  }).catch(() => { $('[data-status]').textContent = 'The workbench could not load its cached evidence. The main feed remains available.'; });
})();
