/* Shared evidence loader. Browser interactions use only the published snapshot. */
(() => {
  'use strict';
  const core = window.SwiftIOCGroupCore;
  const ready = fetch(`${document.body.dataset.iocRoot || '.'}/group_evidence.json`, { cache: 'no-cache' })
    .then((response) => { if (!response.ok) throw new Error('Evidence unavailable'); return response.json(); })
    .then((data) => core.build(data));
  ready.catch(() => {});
  const url = (group, view = 'overview') => `groups.html#${new URLSearchParams({ group, view })}`;
  const pending = new WeakMap();
  window.SwiftIOCGroupIntel = {
    ready, url,
    cve(model, value) { return model?.byIdentity.get(`cve:${core.identity(value, 'cve')}`) || null; },
    receipt(model, record, group) { return core.receipt(model, record, group); },
    decorate(type, value, host) {
      const token = {};
      pending.set(host, token);
      ready.then((model) => {
        if (!host.isConnected || pending.get(host) !== token) return;
        if (host.matches('[data-lookup-result]') && (host.dataset.iocType !== type || host.dataset.iocValue !== value)) return;
        host.querySelectorAll('.group-evidence-attachment').forEach((node) => node.remove());
        const record = model.byIdentity.get(`${type}:${core.identity(value, type)}`);
        if (!record?.groups.length) return;
        const link = document.createElement('a');
        link.className = 'group-evidence-attachment group-evidence-badge';
        link.textContent = `${record.groups.length} reported group ${record.groups.length === 1 ? 'link' : 'links'} ↗`;
        link.title = `${record.groups.join(', ')} · Reported association; current use is not established.`;
        const params = new URLSearchParams({ view: type === 'cve' ? 'cves' : 'iocs', q: value });
        link.href = `groups.html#${params}`;
        host.appendChild(link);
      }).catch(() => {});
    },
  };
  const summary = document.querySelector('[data-group-summary]');
  if (summary) ready.then((model) => {
    const cves = model.records.filter((r) => r.kind === 'cves');
    summary.textContent = `${model.groups.size} groups · ${model.records.filter((r) => r.kind === 'iocs').length.toLocaleString()} IOCs · ${cves.length} CVEs · ${cves.filter((r) => r.matched).length} CVEs also in SwiftIOC`;
  }).catch(() => { summary.textContent = 'Group evidence is temporarily unavailable. The main feed remains available.'; });
})();
