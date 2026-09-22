/* Public, derived group evidence. The API key and raw provider responses stay server-side. */
(() => {
  'use strict';
  const root = document.querySelector('[data-group-intel-root]');
  if (!root) return;
  const status = root.querySelector('[data-group-status]');
  const list = root.querySelector('[data-group-list]');
  const groupFilter = root.querySelector('[data-group-filter]');
  const coverage = root.querySelector('[data-group-coverage]');
  const search = root.querySelector('[data-group-search]');
  const more = root.querySelector('[data-group-more]');
  const profile = root.querySelector('[data-group-profile]');
  const buttons = [...root.querySelectorAll('[data-group-kind]')];
  let data = null;
  let kind = 'iocs';
  let limit = 50;

  const element = (tag, content, className) => {
    const node = document.createElement(tag);
    node.textContent = content;
    if (className) node.className = className;
    return node;
  };
  const groupUrl = (name) => `https://ransomware.live/group/${encodeURIComponent(name)}`;
  const normalise = (value) => String(value || '').trim().replaceAll('[.]', '.').toLowerCase();
  const identity = (value, type) => {
    const cleaned = String(value || '').trim().replaceAll('[.]', '.').replace(/^hxxps:/i, 'https:').replace(/^hxxp:/i, 'http:');
    return type === 'url' ? cleaned : cleaned.toLowerCase();
  };
  const groupsFor = (names) => {
    const wrapper = element('span', '', 'group-evidence-groups');
    names.forEach((name) => {
      const link = element('a', name, 'group-evidence-group');
      link.href = groupUrl(name);
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      wrapper.appendChild(link);
    });
    return wrapper;
  };
  const render = () => {
    if (!data) return;
    profile.replaceChildren();
    profile.hidden = !groupFilter.value;
    if (groupFilter.value) {
      const selectedGroup = data.groups.find((item) => item.name === groupFilter.value);
      if (selectedGroup) {
        profile.appendChild(element('strong', `${selectedGroup.name} · ${selectedGroup.cves.length} reported CVEs · ${selectedGroup.ttps.length} ATT&CK techniques`));
        const techniques = element('div', '', 'group-evidence-groups');
        selectedGroup.ttps.forEach((id) => {
          const link = element('a', id, 'group-evidence-group');
          link.href = `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
          link.target = '_blank';
          link.rel = 'noopener noreferrer';
          techniques.appendChild(link);
        });
        profile.appendChild(techniques);
      }
    }
    const term = normalise(search.value);
    const selected = groupFilter.value;
    const records = data[kind].filter((item) => {
      if (selected && !item.groups.includes(selected)) return false;
      if (coverage.value === 'matched' && !item.in_swiftioc) return false;
      if (coverage.value === 'new' && item.in_swiftioc) return false;
      return !term || normalise(kind === 'cves' ? item.cve_id : item.indicator).includes(term);
    });
    list.replaceChildren();
    const fragment = document.createDocumentFragment();
    records.slice(0, limit).forEach((item) => {
      const card = element('article', '', 'group-evidence-card');
      const value = kind === 'cves' ? item.cve_id : item.indicator;
      card.appendChild(element('code', value, 'group-evidence-value'));
      card.appendChild(element('span', item.in_swiftioc ? 'In SwiftIOC' : 'Research candidate',
        item.in_swiftioc ? 'group-evidence-match' : 'group-evidence-candidate'));
      if (kind === 'iocs') card.appendChild(element('span', item.type, 'group-evidence-type'));
      card.appendChild(groupsFor(item.groups));
      fragment.appendChild(card);
    });
    list.appendChild(fragment);
    status.textContent = `${records.length.toLocaleString()} group-linked ${kind === 'cves' ? 'CVEs' : 'IOCs'} · ${data.groups.length} groups · Snapshot ${new Date(data.generated_at).toLocaleString()}. ${records.length ? `Showing ${Math.min(limit, records.length).toLocaleString()}.` : 'No matching evidence.'}`;
    more.hidden = records.length <= limit;
  };
  const decorate = (type, value, host) => {
    if (!host || !data) return;
    host.querySelectorAll('.group-evidence-attachment').forEach((node) => node.remove());
    const matches = type === 'cve'
      ? data.cves.filter((item) => identity(item.cve_id, 'cve') === identity(value, 'cve'))
      : data.iocs.filter((item) => item.type === type && identity(item.indicator, type) === identity(value, type));
    if (!matches.length) return;
    const note = element('div', '', 'group-evidence-attachment');
    note.appendChild(element('strong', 'Ransomware.live group association: '));
    note.appendChild(groupsFor(matches[0].groups));
    note.appendChild(element('small', 'Reported association; not proof of current use or attribution.'));
    host.appendChild(note);
  };
  const ready = fetch(`${document.body.dataset.iocRoot || '.'}/group_evidence.json`, { cache: 'no-cache' })
    .then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.json();
    })
    .then((payload) => {
      if (payload.schema_version !== 1 || !Array.isArray(payload.groups) || !Array.isArray(payload.iocs) || !Array.isArray(payload.cves)) throw new Error('Invalid group evidence');
      data = payload;
      payload.groups.forEach((group) => {
        const option = element('option', group.name);
        option.value = group.name;
        groupFilter.appendChild(option);
      });
      render();
      document.querySelectorAll('[data-cve-id]').forEach((card) => decorate('cve', card.dataset.cveId, card));
      const lookup = document.querySelector('[data-lookup-result][data-ioc-type][data-ioc-value]');
      if (lookup) decorate(lookup.dataset.iocType, lookup.dataset.iocValue, lookup);
    })
    .catch(() => {
      status.textContent = 'Group evidence is not available yet. Configure RANSOMWARE_LIVE_API_KEY and run the collector; the main IOC and CVE feeds remain available.';
    });
  window.SwiftIOCGroupIntel = {
    decorate(type, value, host) { ready.then(() => decorate(type, value, host)); },
  };
  buttons.forEach((button) => button.addEventListener('click', () => {
    kind = button.dataset.groupKind;
    limit = 50;
    buttons.forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
    render();
  }));
  [groupFilter, coverage, search].forEach((input) => input.addEventListener('input', () => { limit = 50; render(); }));
  more.addEventListener('click', () => { limit += 50; render(); });
})();
