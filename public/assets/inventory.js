(() => {
  'use strict';
  const core = window.SwiftIOCInventory;
  const root = document.querySelector('[data-inventory-root]');
  if (!root || !core) return;
  const get = (name) => root.querySelector(`[data-inventory-${name}]`);
  let assets = [], snapshot = null, report = null, limit = 20, importId = 0, newest = 0;
  const save = (value, filename) => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2) + '\n'], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  const add = (parent, tag, value) => {
    const node = document.createElement(tag); node.textContent = value; parent.appendChild(node); return node;
  };
  const render = (notice = '') => {
    get('results').replaceChildren();
    get('export').disabled = !report;
    get('clear').disabled = !assets.length;
    get('more').hidden = !report || report.findings.length <= limit;
    get('status').textContent = notice || (!assets.length ? 'Import an inventory to begin. No match does not mean safe.'
      : !report ? `${assets.length} assets loaded. Waiting for a usable CVE snapshot; export is disabled.`
      : `${assets.length} assets · ${report.findings.length} findings · ${report.unmatched_assets.length} assets without a match. Snapshot: ${report.snapshot_generated_at}. No match does not mean safe.${report.truncated ? ' Report limit reached; some assets were not fully assessed. Split the inventory into smaller files.' : ''}`);
    if (!report) return;
    for (const finding of report.findings.slice(0, limit)) {
      const card = add(get('results'), 'article', '');
      add(card, 'h3', `${finding.asset.id} · ${finding.cve_id}`);
      add(card, 'p', `${finding.status.replaceAll('-', ' ')} · ${finding.exploitation_status.replaceAll('_', ' ')} · ${finding.asset.exposure} exposure · ${finding.asset.importance} importance`);
      add(card, 'p', `${finding.asset.vendor} / ${finding.asset.product} / ${finding.asset.version || 'version unknown'}`);
      add(card, 'p', finding.reason);
      add(card, 'p', `Action: ${finding.required_action}`);
      const details = add(card, 'details', ''); add(details, 'summary', 'Matching evidence and provider reports');
      add(details, 'pre', JSON.stringify({ cisa_product_match: finding.cisa_product_match, nvd_rules: finding.nvd_rules, reports: finding.reports }, null, 2));
    }
    if (report.unmatched_assets.length) add(get('results'), 'p', `No retained match: ${report.unmatched_assets.map((asset) => asset.id).join(', ')}. Check naming, mappings, and collection coverage.`);
  };
  const rebuild = () => {
    report = assets.length && snapshot ? core.buildReport(assets, snapshot.items, snapshot.generated_at) : null;
    limit = 20; render();
  };
  window.addEventListener('swiftioc:vulnerability-snapshot', (event) => {
    const next = event.detail, time = Date.parse(next?.generated_at);
    snapshot = next && Number.isFinite(time) && time <= Date.now() && time >= newest ? next : null;
    if (snapshot) newest = time;
    rebuild();
  });
  get('file').addEventListener('change', async (event) => {
    const request = ++importId;
    const file = event.target.files?.[0]; if (!file) return;
    try {
      if (file.size > 500000) throw new Error('Inventory must be at most 500 KB.');
      const contents = await file.text();
      if (request !== importId) return;
      const next = core.parseInventory(JSON.parse(contents));
      assets = next; rebuild();
    } catch (error) {
      if (request === importId) render(`Import rejected: ${error.message}. ${assets.length ? 'Previous inventory retained.' : 'No inventory loaded.'}`);
    } finally { if (request === importId) event.target.value = ''; }
  });
  get('clear').addEventListener('click', () => { ++importId; assets = []; get('file').value = ''; rebuild(); });
  get('more').addEventListener('click', () => { limit += 20; render(); });
  get('export').addEventListener('click', () => { if (report) save(report, 'swiftioc-exposure-report.json'); });
  get('sample').addEventListener('click', () => save({ schema_version: 1, assets: [
    { id: 'example-edge-service', vendor: 'Example Vendor', product: 'Example Server', version: '2.4.1',
      cpe_vendor: 'example_vendor', cpe_product: 'example_server', exposure: 'internet', importance: 'critical' },
  ] }, 'swiftioc-inventory-sample.json'));
  render();
})();
