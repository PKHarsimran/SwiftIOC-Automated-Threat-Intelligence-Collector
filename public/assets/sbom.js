(() => {
  'use strict';
  const root = document.querySelector('[data-sbom-root]'), core = window.SwiftIOCSbom;
  if (!root || !core) return;
  const get = (name) => root.querySelector(`[data-sbom-${name}]`);
  const add = (parent, tag, text) => { const node = document.createElement(tag); node.textContent = text; parent.appendChild(node); return node; };
  let parsed = null, busy = false, importId = 0;
  function render(rows = null, notice = '') {
    get('results').replaceChildren(); get('check').disabled = busy || !parsed; get('clear').disabled = busy || !parsed;
    get('status').textContent = notice || (parsed ? `${parsed.components.length} versioned packages ready; ${parsed.skipped} without usable identity skipped. Check with OSV only if you agree to send these package URLs and versions directly to OSV.dev.` : 'Import a supported SBOM to begin. No match is not proof of safety.');
    if (!rows) return;
    const affected = rows.filter((row) => row.vulnerabilities.length);
    add(get('results'), 'p', `${affected.length} of ${rows.length} queried packages have OSV advisories. Results reflect OSV coverage at query time; no match is not proof of safety.`);
    for (const row of affected.slice(0, 50)) {
      const card = add(get('results'), 'article', '');
      add(card, 'h3', `${row.name}${row.version ? ` · ${row.version}` : ''}`);
      add(card, 'p', `${row.vulnerabilities.length} advisory IDs${row.incomplete ? ' · OSV result paginated; list incomplete' : ''}`);
      const list = add(card, 'div', '');
      for (const id of row.vulnerabilities.slice(0, 12)) {
        const anchor = add(list, 'a', `${id} ↗ `); anchor.href = `https://osv.dev/vulnerability/${encodeURIComponent(id)}`; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer';
      }
      if (row.vulnerabilities.length > 12) add(card, 'p', `Showing 12 of ${row.vulnerabilities.length} advisory IDs.`);
    }
    if (affected.length > 50) add(get('results'), 'p', `Showing 50 of ${affected.length} affected packages. Split the SBOM for a smaller review.`);
    if (rows.some((row) => row.incomplete)) add(get('results'), 'p', 'Some OSV responses were paginated, so their advisory lists are incomplete. Review those packages directly in OSV.');
  }
  get('file').addEventListener('change', async (event) => {
    const id = ++importId, file = event.target.files?.[0]; if (!file) return;
    try {
      if (file.size > 1_000_000) throw new Error('SBOM must be at most 1 MB.');
      const next = core.parse(JSON.parse(await file.text()));
      if (id === importId) { parsed = next; render(); }
    } catch (error) { if (id === importId) render(null, `Import rejected: ${error.message} ${parsed ? 'Previous SBOM retained.' : ''}`); }
    finally { if (id === importId) event.target.value = ''; }
  });
  get('clear').addEventListener('click', () => { ++importId; parsed = null; get('file').value = ''; render(); });
  get('check').addEventListener('click', async () => {
    if (!parsed || busy) return;
    busy = true; render(null, `Checking ${parsed.components.length} exact package/version identities with OSV.dev…`);
    try {
      const all = [];
      for (let start = 0; start < parsed.components.length; start += 50) {
        const chunk = parsed.components.slice(start, start + 50);
        const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 25000);
        let response;
        try { response = await fetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: chunk.map((item) => item.query) }), signal: controller.signal }); }
        finally { clearTimeout(timeout); }
        if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}.`);
        const payload = await response.json();
        if (!Array.isArray(payload.results) || payload.results.length !== chunk.length) throw new Error('OSV returned an unexpected result shape.');
        all.push(...payload.results);
      }
      render(core.combine(parsed.components, all), `Checked ${parsed.components.length} package/version identities directly with OSV. Your SBOM has not been sent to SwiftIOC.`);
    } catch (error) { render(null, `OSV check incomplete: ${error.message} No negative result should be inferred.`); }
    finally { busy = false; get('check').disabled = !parsed; get('clear').disabled = !parsed; }
  });
  render();
})();
