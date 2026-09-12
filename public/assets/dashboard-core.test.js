'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const core = require('./dashboard-core.js');

const defaults = {
  type: 'all',
  source: 'all',
  tag: 'all',
  signal: 'all',
  minScore: 0,
  age: 'all',
  search: '',
  limit: 12,
  sort: 'score',
  direction: 'desc',
};

const row = {
  indicator: 'example[.]evil',
  type: 'domain',
  source: 'feed-a,feed-b',
  sourceList: ['feed-a', 'feed-b'],
  sourceCount: 2,
  confidence: 'high',
  tags: ['phishing'],
  tagsLower: ['phishing'],
  firstSeen: '2026-07-15T10:00:00Z',
  lastSeen: '2026-07-15T11:00:00Z',
  bestTimestamp: Date.parse('2026-07-15T11:00:00Z') / 1000,
};

test('refangs raw and defanged indicators consistently', () => {
  assert.equal(core.refang('hxxps://example[.]evil/a'), 'https://example.evil/a');
  assert.equal(
    core.matchesRow(row, { ...defaults, search: 'example.evil' }),
    true
  );
});

test('combines source, tag, signal, score, and age facets', () => {
  const state = {
    ...defaults,
    source: 'feed-b',
    tag: 'phishing',
    signal: 'corroborated',
    minScore: 80,
    age: '24',
  };
  const now = Date.parse('2026-07-15T12:00:00Z') / 1000;
  assert.equal(core.matchesRow(row, state, now), true);
  assert.equal(core.matchesRow(row, { ...state, source: 'feed-c' }, now), false);
});

test('supports OR within multi-select facets and AND across facets', () => {
  const state = {
    ...defaults,
    types: ['ipv4', 'domain'],
    sources: ['feed-b', 'feed-c'],
    tags: ['phishing', 'c2'],
    scoreBands: ['high', 'elevated'],
    ageBands: ['day', 'week'],
  };
  const now = Date.parse('2026-07-15T12:00:00Z') / 1000;
  assert.equal(core.matchesRow(row, state, now), true);
  assert.equal(
    core.matchesRow(row, { ...state, tags: ['ransomware'] }, now),
    false
  );
});

test('rejects future timestamps and stale rows for age filters', () => {
  const now = Date.parse('2026-07-15T12:00:00Z') / 1000;
  assert.equal(
    core.matchesRow({ ...row, bestTimestamp: now + 3600 }, { ...defaults, age: '24' }, now),
    false
  );
  assert.equal(
    core.matchesRow({ ...row, bestTimestamp: now - 25 * 3600 }, { ...defaults, age: '24' }, now),
    false
  );
});

test('sorts missing and legacy scores deterministically', () => {
  const medium = { ...row, indicator: 'b', confidence: 'medium', sourceCount: 1 };
  const scored = { ...row, indicator: 'a', score: 95, sourceCount: 1 };
  const values = [medium, scored].sort((a, b) => core.compareRows(a, b, defaults));
  assert.deepEqual(values.map((entry) => entry.indicator), ['a', 'b']);
});

test('round-trips view state while preserving unrelated parameters', () => {
  const state = {
    ...defaults,
    type: 'domain',
    source: 'feed-a',
    search: 'example[.]evil',
    limit: 50,
    sort: 'lastSeen',
  };
  const url = core.writeViewUrl('https://example.test/?campaign=docs', state, true);
  assert.equal(url.searchParams.get('campaign'), 'docs');
  const parsed = core.readViewState(url.search, url.hash);
  assert.equal(parsed.type, 'domain');
  assert.equal(parsed.source, 'feed-a');
  assert.equal(parsed.search, 'example[.]evil');
  assert.equal(parsed.limit, 50);
  assert.equal(parsed.sort, 'lastSeen');
});

test('round-trips repeated multi-select URL parameters', () => {
  const state = {
    ...defaults,
    types: ['domain', 'ipv4'],
    sources: ['feed-a', 'feed-b'],
    tags: ['c2', 'phishing'],
    scoreBands: ['high', 'elevated'],
    ageBands: ['day', 'week'],
  };
  const url = core.writeViewUrl('https://example.test/', state);
  const parsed = core.readViewState(url.search, url.hash);
  assert.deepEqual(parsed.types, state.types);
  assert.deepEqual(parsed.sources, state.sources);
  assert.deepEqual(parsed.tags, state.tags);
  assert.deepEqual(parsed.scoreBands, state.scoreBands);
  assert.deepEqual(parsed.ageBands, state.ageBands);
});

test('does not expose free-text search unless sharing is explicit', () => {
  const state = { ...defaults, search: 'sensitive-indicator' };
  const url = core.writeViewUrl('https://example.test/', state, false);
  assert.equal(url.search, '');
  assert.equal(url.hash, '');
});

test('sanitizes unsupported URL-controlled facets', () => {
  const state = core.readViewState('?signal=urgent&score=999&age=forever');
  assert.equal(state.signal, 'all');
  assert.equal(state.minScore, 0);
  assert.equal(state.age, 'all');
});

test('normalizes shared filter values and exports spreadsheet-safe CSV', () => {
  const state = core.readViewState('?type=DOMAIN&source=Feed-A&signal=HIGH&score_band=HIGH&age_band=WEEK');
  assert.deepEqual(state.types, ['domain']);
  assert.deepEqual(state.sources, ['feed-a']);
  assert.equal(state.signal, 'high');
  assert.deepEqual(state.scoreBands, ['high']);
  assert.deepEqual(state.ageBands, ['week']);
  const csv = core.rowsToCsv([{
    indicator: '=HYPERLINK("https://example.invalid")',
    type: 'domain',
    tags: ['phishing', 'credential-theft'],
  }]);
  assert.match(csv, /"'=HYPERLINK\(""https:\/\/example\.invalid""\)"/);
  assert.match(csv, /"phishing, credential-theft"/);
});

test('exports an empty CSV with only its header when no rows are supplied', () => {
  const csv = core.rowsToCsv([]);
  assert.equal(csv.split('\r\n').filter(Boolean).length, 1);
  assert.match(csv, /"Indicator"/);
});

test('sanitizes and deduplicates browser-local investigation rows', () => {
  const rows = core.normaliseInvestigationRows([
    { ...row, score: 120, sourceList: ['feed-a', '', 'feed-b'] },
    { ...row, score: 50 },
    null,
    { type: 'domain' },
    { indicator: 'second.example', type: 'domain', score: Number.NaN },
  ]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].score, 100);
  assert.deepEqual(rows[0].sourceList, ['feed-a', 'feed-b']);
  assert.equal(core.investigationKey(rows[0]), 'domain\u0000example[.]evil');
  assert.equal(Object.hasOwn(rows[1], 'score'), false);
  assert.deepEqual(core.normaliseInvestigationRows({ rows: [] }), []);
});

test('preserves case-sensitive URL paths in investigation identity', () => {
  const upper = { indicator: 'https://host/Payload?id=ABC', type: 'url' };
  const lowerPath = { indicator: 'https://host/payload?id=ABC', type: 'url' };
  assert.notEqual(core.investigationKey(upper), core.investigationKey(lowerPath));
  assert.equal(core.normaliseInvestigationRows([upper, lowerPath]).length, 2);

  assert.equal(
    core.investigationKey({ indicator: 'Example[.]COM', type: 'domain' }),
    core.investigationKey({ indicator: 'example[.]com', type: 'domain' })
  );
});

test('builds type-aware Sigma detections from the investigation queue', () => {
  const sigma = core.rowsToSigma([
    { indicator: '1[.]2[.]3[.]4', type: 'ipv4' },
    { indicator: 'evil[.]example', type: 'domain' },
    { indicator: 'hxxps://evil[.]example/dropper', type: 'url' },
  ]);
  assert.match(sigma, /category: network_connection/);
  assert.match(sigma, /"1\.2\.3\.4"/);
  assert.match(sigma, /category: dns/);
  assert.match(sigma, /"\.evil\.example"/);
  assert.doesNotMatch(sigma, /dropper/);
});

test('builds deterministic Suricata rules and rejects injected values', () => {
  const rows = [
    { indicator: '1[.]2[.]3[.]4', type: 'ipv4' },
    { indicator: 'evil[.]example', type: 'domain' },
    { indicator: 'evil.com"; sid:1;', type: 'domain' },
  ];
  const first = core.rowsToSuricata(rows);
  const second = core.rowsToSuricata(rows.slice().reverse());
  assert.equal(first, second);
  assert.equal((first.match(/\bsid:\d+;/g) || []).length, 3);
  assert.match(first, /1\.2\.3\.4/);
  assert.match(first, /dotprefix; content:"\.evil\.example"/);
  assert.doesNotMatch(first, /sid:1;/);
});

test('accepts IPv4-embedded IPv6 observables in browser detection exports', () => {
  const rows = core.detectionRows([
    { indicator: '::ffff:192.0.2.1', type: 'ipv6' },
    { indicator: '::ffff:192.0.2.0/120', type: 'ipv6_cidr' },
  ]);
  assert.deepEqual(rows.map((row) => row.indicator), [
    '::ffff:192.0.2.1',
    '::ffff:192.0.2.0/120',
  ]);
});

test('builds deterministic campaign pivots and omits singleton relationships', () => {
  const rows = [
    { ...row, indicator: 'one.example', tags: ['ransomware', 'feed-a', 'critical'], sourceList: ['feed-a'] },
    { ...row, indicator: 'two.example', tags: ['ransomware', 'feed-a', 'critical'], sourceList: ['feed-a', 'feed-b'], score: 90 },
    { ...row, indicator: 'three.example', tags: ['singleton'], sourceList: ['feed-b'], score: 70 },
  ];
  const graph = core.buildCampaignGraph(rows, { mode: 'tags' });
  assert.deepEqual(graph.stats, {
    pivots: 1,
    indicators: 2,
    relationships: 2,
    highScore: 2,
    corroborated: 0,
    averageScore: 85,
    tagPivots: 1,
    sourcePivots: 0,
    availableProviders: 0, mappedProviders: 0, aggregates: 0, unmappedFeeds: 0,
  });
  assert.equal(graph.nodes.find((node) => node.kind === 'pivot').label, 'ransomware');
  assert.equal(graph.nodes.some((node) => node.label === 'singleton'), false);
  assert.equal(graph.edges.every((edge) => edge.kind === 'tag'), true);
  assert.deepEqual(
    core.buildCampaignGraph(rows.slice().reverse(), { mode: 'tags' }),
    graph
  );
});

test('campaign graph respects source mode and graph-size caps', () => {
  const rows = Array.from({ length: 20 }, (_, index) => ({
    ...row,
    indicator: `${index}.example.test`,
    tags: ['shared-tag'],
    sourceList: ['shared-source'],
    score: 100 - index,
  }));
  const graph = core.buildCampaignGraph(rows, {
    mode: 'sources',
    maxPivots: 1,
    maxIndicators: 5,
  });
  assert.equal(graph.stats.pivots, 1);
  assert.equal(graph.stats.indicators, 5);
  assert.equal(graph.nodes.find((node) => node.kind === 'pivot').pivotKind, 'source');
});

test('campaign graph does not invent relationships for missing sources', () => {
  const rows = [
    { ...row, indicator: 'one.example', source: 'unknown', sourceList: [], sourceCount: 0, tags: [] },
    { ...row, indicator: 'two.example', source: 'unknown', sourceList: [], sourceCount: 0, tags: [] },
  ];
  const graph = core.buildCampaignGraph(rows, { mode: 'sources' });
  assert.equal(graph.nodes.length, 0);
  assert.equal(graph.edges.length, 0);
});

test('campaign graph prunes pivots disconnected by the indicator cap', () => {
  const rows = ['alpha', 'beta', 'gamma'].flatMap((tag, tagIndex) =>
    [0, 1].map((index) => ({
      ...row,
      indicator: `${tag}-${index}.example`,
      tags: [tag],
      score: 100 - tagIndex * 20,
    }))
  );
  const graph = core.buildCampaignGraph(rows, {
    mode: 'tags',
    maxPivots: 3,
    maxIndicators: 2,
  });
  assert.equal(graph.stats.pivots, 2);
  assert.equal(graph.stats.tagPivots, 2);
  assert.equal(graph.nodes.filter((node) => node.kind === 'pivot').length, 2);
  assert.equal(graph.edges.length, 2);
});

test('dashboard markup keeps IDs and labelled controls consistent', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, 'styles.css'), 'utf8');
  const ids = Array.from(html.matchAll(/\sid="([^"]+)"/g), (match) => match[1]);
  assert.equal(new Set(ids).size, ids.length, 'IDs must be unique');
  for (const match of html.matchAll(/<label[^>]+for="([^"]+)"/g)) {
    assert.ok(ids.includes(match[1]), `Missing labelled control #${match[1]}`);
  }
  assert.equal((html.match(/<main\b/g) || []).length, 1);
  assert.equal((html.match(/<style\b/g) || []).length, 0);
  assert.ok(
    html.indexOf('src="assets/dashboard-core.js') <
      html.indexOf('src="assets/dashboard.js'),
    'Pure helpers must load before the dashboard controller'
  );
  assert.equal(
    /<\/a>\s*>\s*<a\b/.test(html),
    false,
    'Export links must not render stray greater-than characters'
  );
  assert.match(html, /data-preview-download/);
  assert.match(html, /data-preview-download-note/);
  assert.match(html, /data-investigation-root/);
  assert.match(html, /data-detection-artifact="sigma\/network-iocs\.yml"[^>]*hidden/);
  assert.match(html, /data-detection-artifact="sigma\/dns-iocs\.yml"[^>]*hidden/);
  assert.match(html, /data-investigation-list/);
  assert.match(html, /data-investigation-sigma/);
  assert.match(html, /data-investigation-suricata/);
  assert.match(html, /data-campaign-graph/);
  assert.match(html, /data-campaign-graph[\s\S]*?role="group"/);
  assert.match(html, /data-campaign-density/);
  assert.match(html, /data-campaign-related-list/);
  assert.match(html, /data-campaign-reference/);
  assert.match(html, /data-tool-disclosure/);
  assert.match(html, /data-delta-root/);
  assert.match(html, /iocs\/delta\.jsonl/);
  assert.match(html, /iocs\/taxii2-envelope\.json/);
  assert.equal(
    (html.match(/<a\b/g) || []).length,
    (html.match(/<\/a>/g) || []).length,
    'Every link must have a complete closing tag'
  );
  assert.match(
    css,
    /\[hidden\]\s*\{\s*display:\s*none\s*!important;/,
    'Responsive display rules must not expose hidden detail rows'
  );
});

test('discovery ranks actual source names, deduplicates IOCs, and explains corroboration', () => {
  const a = { ...row, indicator: 'a.example', sourceList: ['Feed-A', 'feed-a', 'unknown'], sourceCount: 99 };
  const b = { ...row, indicator: 'b.example', sourceList: ['Feed-A', 'Feed-B'] };
  const result = core.buildDiscovery([a, b, b], 'corroborated');
  assert.equal(result.sampleSize, 2);
  assert.equal(result.total, 1);
  assert.equal(result.findings[0].row.indicator, 'b.example');
  assert.match(result.findings[0].reason, /do not establish source independence/);
});

test('recent discovery excludes future, invalid, and old sightings', () => {
  const now = Date.parse('2026-09-08T12:00:00Z') / 1000;
  const rows = [
    { ...row, indicator: 'fresh.example', lastSeen: '2026-09-08T11:00:00Z' },
    { ...row, indicator: 'future.example', lastSeen: '2026-09-09T11:00:00Z' },
    { ...row, indicator: 'old.example', lastSeen: '2026-09-06T11:00:00Z' },
    { ...row, indicator: 'invalid.example', lastSeen: 'not a date' },
  ];
  const result = core.buildDiscovery(rows, 'recent', now);
  assert.deepEqual(result.findings.map(({ row }) => row.indicator), ['fresh.example']);
});

test('uncommon discovery measures distinct indicators and omits generic and source tags', () => {
  const rows = Array.from({ length: 5 }, (_, i) => ({
    ...row, indicator: `${i}.example`, tags: ['high', 'feed-a', 'shared', ...(i === 0 ? ['unusual', 'unusual'] : [])],
  }));
  const result = core.buildDiscovery(rows, 'uncommon');
  assert.equal(result.total, 1);
  assert.equal(result.findings[0].label, 'unusual');
  assert.match(result.findings[0].reason, /1 of 5/);
  assert.deepEqual(core.buildDiscovery(rows.slice().reverse(), 'uncommon'), result);
  assert.equal(core.buildDiscovery([], 'uncommon').findings.length, 0);
});

test('CVE provider and generic tags never become observable graph or discovery relationships', () => {
  const cves = ['CVE-2020-1234', 'CVE-2020-5678'].map((indicator) => ({
    ...row, type: 'cve', indicator, tags: ['cve', 'nvd'], tagsLower: ['cve', 'nvd'],
  }));
  assert.deepEqual(core.buildCampaignGraph([...cves, row]), core.buildCampaignGraph([row]));
  assert.deepEqual(core.buildDiscovery([...cves, row], 'corroborated'), core.buildDiscovery([row], 'corroborated'));
});

test('vulnerability filters keep exact CVE records and separate severity from exploitation', () => {
  const items = [
    { cve_id: 'CVE-2020-9999', exploitation_status: 'not_established', sources: ['nvd'], reports: { nvd: { severity: 'critical' } } },
    { cve_id: 'CVE-2020-5678', exploitation_status: 'reported_exploitation', sources: ['rss'], reports: {} },
    { cve_id: 'CVE-2020-1234', exploitation_status: 'known_exploited', sources: ['kev', 'nvd'], reports: { cisa_kev: { vendor: 'Vendor A', product: 'Router' } } },
  ];
  const before = JSON.stringify(items);
  assert.deepEqual(core.filterVulnerabilities(items).map((r) => r.cve_id), ['CVE-2020-1234', 'CVE-2020-5678', 'CVE-2020-9999']);
  assert.equal(core.filterVulnerabilities(items, 'cve-2020-9999', 'known_exploited').length, 0);
  assert.equal(core.filterVulnerabilities(items, 'ROUTER')[0].cve_id, 'CVE-2020-1234');
  assert.equal(core.filterVulnerabilities(items, 'vendor a')[0].cve_id, 'CVE-2020-1234');
  assert.equal(core.filterVulnerabilities(items, 'nvd').length, 2);
  assert.equal(core.filterVulnerabilities(items, 'missing').length, 0);
  assert.equal(JSON.stringify(items), before);
});


test('vulnerability search indexes each provider description independently of the summary', () => {
  const item = {
    cve_id: 'CVE-1900-1234', exploitation_status: 'known_exploited',
    description: 'Combined summary', reports: {
      cisa_kev: { description: 'CISA-specific remediation context' },
      nvd: { description: 'NVD-specific technical details' },
    },
  };
  for (const query of ['combined summary', 'CISA-SPECIFIC', 'nvd-specific']) {
    assert.deepEqual(core.filterVulnerabilities([item], query), [item]);
  }
  assert.deepEqual(core.filterVulnerabilities([item], 'CISA-specific', 'not_established'), []);
});


test('uncommon discovery omits adapter provider aliases while preserving investigative tags', () => {
  const examples = [
    ['threatfox_export_json', ' ThreatFox '], ['ci_army_list', 'CINS'],
    ['feodo_ipblocklist', 'feodo'], ['sslbl_ja3', 'sslbl'],
    ['spamhaus_drop', 'spamhaus'], ['dshield_block', 'sans-isc'],
    ['openphish_feed', 'openphish'], ['greensnow_blocklist', 'greensnow'],
    ['et_compromised', 'emerging-threats'], ['binarydefense_banlist', 'binarydefense'],
    ['ipsum_level5', 'ipsum'], ['custom-provider-name', 'threatfox'],
  ];
  const rows = examples.map(([source, tag], index) => ({
    ...row, indicator: `provider-${index}.example`, sourceList: [source], tags: [tag],
  }));
  assert.equal(core.buildDiscovery(rows, 'uncommon').total, 0);
  const useful = ['mirai', 'c2', 'phishing', 'scanning', 'tor', 'exit-node'].map((tag, index) => ({
    ...row, indicator: `lead-${index}.example`, sourceList: ['threatfox_export_json'], tags: ['threatfox', tag],
  }));
  const result = core.buildDiscovery([...rows, ...useful], 'uncommon');
  assert.deepEqual(new Set(result.findings.map(({ label }) => label)), new Set(useful.map((r) => r.tags[1])));
  assert.equal(result.sampleSize, rows.length + useful.length);
  assert.match(result.findings[0].reason, /appears on 1 of 18/);
  assert.deepEqual(core.buildDiscovery([...rows, ...useful].reverse(), 'uncommon'), result);
  assert.equal(core.buildDiscovery([{ ...row, sourceList: [], source: 'feed-x, feed-y', tags: ['feed-x', 'feed-y'] }], 'uncommon').total, 0);
});

test('recent discovery accepts equivalent ISO, Unix-number, and numeric-string sightings', () => {
  const now = 1720003600;
  const seen = 1720000000;
  for (const value of [seen, String(seen), ` ${seen} `, seen * 1000, String(seen * 1000), new Date(seen * 1000).toISOString()]) {
    for (const field of ['lastSeen', 'last_seen']) {
      const item = { ...row, lastSeen: undefined, last_seen: undefined, [field]: value };
      const result = core.buildDiscovery([item], 'recent', now);
      assert.equal(result.total, 1, `${field}=${JSON.stringify(value)}`);
      assert.equal(result.findings[0].rank, seen);
    }
  }
  for (const value of [null, undefined, '', '  ', 'NaN', 'Infinity', '1e20', 'not a date', String(now + 1), String(now - 86401)]) {
    // A recent firstSeen/bestTimestamp must never conceal a missing or stale sighting.
    const item = { ...row, lastSeen: value, firstSeen: now, bestTimestamp: now };
    assert.equal(core.buildDiscovery([item], 'recent', now).total, 0, String(value));
  }
  assert.equal(core.buildDiscovery([{ ...row, lastSeen: String(now - 86400) }], 'recent', now).total, 1);
});


const triageNow = Date.parse('2026-09-08T12:00:00Z') / 1000;
const triageItem = (id, status, added, published, modified = published, nvdStatus = 'Analyzed') => ({
  cve_id: id, exploitation_status: status, sources: [], reports: {
    ...(status === 'known_exploited' ? { cisa_kev: { date_added: added } } : {}),
    nvd: { published_at: published, modified_at: modified, status: nvdStatus },
  },
});
const triageItems = [
  triageItem('CVE-2026-1001', 'known_exploited', '2021-01-01', '2021-01-01', '2026-09-08T11:00:00'),
  triageItem('CVE-1900-1002', 'known_exploited', '2026-09-08', '2001-01-01'),
  triageItem('CVE-1900-1003', 'not_established', null, '2026-09-08T10:00:00'),
  triageItem('CVE-2026-1004', 'not_established', null, '2020-01-01', '2026-09-08T11:30:00Z'),
  triageItem('CVE-2026-1005', 'known_exploited', '2026-09-08', '2026-09-08', '2026-09-08', 'Rejected'),
  triageItem('CVE-2026-1006', 'not_established', null, '2030-01-01', '2030-01-01'),
];

test('CVE priority uses exploitation evidence and provider dates, not CVE ID or modification date', () => {
  const before = JSON.stringify(triageItems);
  const result = core.filterVulnerabilities(triageItems, '', 'all', { now: triageNow });
  assert.deepEqual(result.map((r) => r.cve_id), ['CVE-1900-1002', 'CVE-2026-1001', 'CVE-1900-1003', 'CVE-2026-1004', 'CVE-2026-1006']);
  const withRejected = core.filterVulnerabilities(triageItems, '', 'all', { now: triageNow, includeRejected: true });
  assert.equal(withRejected.at(-1).cve_id, 'CVE-2026-1005');
  assert.equal(JSON.stringify(triageItems), before);
});

test('CVE views distinguish recent catalog addition, disclosure, and modification', () => {
  const ids = (view, status = 'all') => core.filterVulnerabilities(triageItems, '', status, { now: triageNow, view }).map((r) => r.cve_id);
  assert.deepEqual(ids('kev30'), ['CVE-1900-1002']);
  assert.deepEqual(ids('published7'), ['CVE-1900-1003']);
  assert.deepEqual(ids('published7', 'known_exploited'), []);
  assert.deepEqual(ids('updated7'), ['CVE-2026-1004', 'CVE-2026-1001', 'CVE-1900-1003']);
  assert.deepEqual(core.filterVulnerabilities(triageItems, 'CVE-1900-1002', 'all', { now: triageNow, view: 'kev30' }).map((r) => r.cve_id), ['CVE-1900-1002']);
});

test('CVE dates treat offset-free NVD timestamps as UTC and reject invalid/future dates', () => {
  const expected = Date.parse('2026-09-08T10:00:00Z') / 1000;
  for (const date of ['2026-09-08T10:00:00', '2026-09-08T10:00:00Z', '2026-09-08T15:30:00+05:30']) {
    assert.equal(core.vulnerabilityFacts(triageItem('CVE-1900-1234', 'not_established', null, date), triageNow).published, expected);
  }
  for (const date of [null, '', 'not a date', '2030-01-01', '2026-02-30', '2026-13-01']) {
    const item = triageItem('CVE-1900-1234', 'not_established', null, date);
    assert.equal(core.vulnerabilityFacts(item, triageNow).published, null);
    assert.equal(core.filterVulnerabilities([item], '', 'all', { now: triageNow, view: 'published7' }).length, 0);
  }
  const boundary = new Date((triageNow - 7 * 86400) * 1000).toISOString();
  assert.equal(core.filterVulnerabilities([triageItem('CVE-1900-1234', 'not_established', null, boundary)], '', 'all', { now: triageNow, view: 'published7' }).length, 1);
});


test('exploited and ransomware views require explicit evidence and never fall back to generic CVEs', () => {
  const confirmed = triageItem('CVE-1900-1234', 'known_exploited', '2026-09-07', '2020-01-01');
  confirmed.reports.cisa_kev.ransomware_use = 'Known';
  const unknown = triageItem('CVE-1900-1235', 'known_exploited', '2026-09-06', '2020-01-01');
  unknown.reports.cisa_kev.ransomware_use = 'Unknown';
  const generic = triageItem('CVE-1900-1236', 'not_established', null, '2026-09-08');
  const items = [generic, unknown, confirmed];
  assert.deepEqual(core.filterVulnerabilities(items, '', 'all', {view: 'exploited', now: triageNow}).map((r) => r.cve_id), [confirmed.cve_id, unknown.cve_id]);
  assert.deepEqual(core.filterVulnerabilities(items, '', 'all', {view: 'ransomware', now: triageNow}), [confirmed]);
  assert.equal(core.filterVulnerabilities([generic], '', 'all', {view: 'exploited', now: triageNow}).length, 0);
  assert.equal(core.filterVulnerabilities(items, '', 'not_established', {view: 'exploited', now: triageNow}).length, 0);
  for (const value of ['Unknown', 'Not known', '', null]) {
    confirmed.reports.cisa_kev.ransomware_use = value;
    assert.equal(core.vulnerabilityFacts(confirmed, triageNow).ransomware, false);
  }
});

test('vulnerability release uses coordinated new asset cache keys', () => {
  const html = fs.readFileSync(path.join(__dirname, '../index.html'), 'utf8');
  for (const asset of ['styles.css', 'dashboard-core.js', 'dashboard.js']) {
    assert.ok(html.includes(`assets/${asset}?v=36`));
  }
});

test('compact preview honors mobile defaults and explicit shared row counts', () => {
  assert.equal(core.readViewState('', '', 6).limit, 6);
  assert.equal(core.readViewState('?rows=12', '', 6).limit, 12);
  assert.equal(core.readViewState('?rows=999', '', 6).limit, 6);
  assert.equal(core.readViewState('', '', -1).limit, 12);
  const compact = core.readViewState('?rows=6');
  const url = core.writeViewUrl('https://example.test/', compact);
  assert.equal(core.readViewState(url.search, url.hash).limit, 6);
  const mobileTwelve = core.writeViewUrl('https://example.test/', defaults, false, 6);
  assert.equal(core.readViewState(mobileTwelve.search, '', 6).limit, 12);
  const sharedDesktop = core.writeViewUrl('https://example.test/', defaults, true);
  assert.equal(core.readViewState(sharedDesktop.search, sharedDesktop.hash, 6).limit, 12);
});

test('provider graph groups abuse.ch adapters and excludes directory and aggregate corroboration', () => {
  const rows = [0, 1].map((i) => ({ ...row, indicator: `192.0.2.${i + 1}`, type: 'ipv4',
    sourceList: ['threatfox_export_json', 'urlhaus_recent_urls', 'THREATFOX', 'ipsum_level5', 'tor_exit_nodes'],
    sourceCount: 99, tags: ['threatfox', 'urlhaus', 'cins', 'export_json', 'scanner'],
  }));
  const graph = core.buildCampaignGraph(rows, { mode: 'all' });
  const providers = graph.nodes.filter((node) => node.pivotKind === 'source');
  assert.deepEqual(providers.map((node) => node.label).sort(), ['IPsum (aggregate)', 'abuse.ch']);
  assert.equal(graph.stats.corroborated, 0);
  assert.equal(graph.stats.mappedProviders, 1);
  assert.equal(graph.nodes.filter((node) => node.kind === 'indicator').every((node) => node.sourceCount === 1), true);
  assert.deepEqual(graph.nodes.filter((node) => node.pivotKind === 'tag').map((node) => node.label), ['scanner']);
  assert.equal(providers.find((node) => node.label === 'abuse.ch').feeds.includes('urlhaus_recent_urls'), true);
});

test('provider sampling retains smaller genuine providers without inventing sources', () => {
  const rows = Array.from({ length: 30 }, (_, i) => ({ ...row, indicator: `ioc-${i}.example`,
    sourceList: [i < 28 ? 'threatfox_export_json' : 'ci_army_list'], score: i < 28 ? 99 : 60,
  }));
  const graph = core.buildCampaignGraph(rows, { mode: 'sources', maxIndicators: 4 });
  assert.equal(graph.stats.indicators, 4);
  assert.deepEqual(graph.nodes.filter((node) => node.kind === 'pivot').map((node) => node.label).sort(), ['CINS Army', 'abuse.ch']);
  assert.equal(graph.nodes.filter((node) => node.kind === 'pivot').every((node) => node.count > 0), true);
  assert.deepEqual(core.buildCampaignGraph(rows.slice().reverse(), { mode: 'sources', maxIndicators: 4 }), graph);
  const one = core.buildCampaignGraph(rows.slice(0, 28), { mode: 'sources', maxIndicators: 24 });
  assert.equal(one.stats.sourcePivots, 1);
  assert.equal(one.stats.indicators, 24);
});

const briefingItem = (id = 'CVE-2026-1234') => ({
  cve_id: id, exploitation_status: 'known_exploited', sources: ['kev'],
  reports: { cisa_kev: { vendor: 'ExampleVendor', product: 'Router', required_action: 'Apply update',
    ransomware_use: 'Unknown', date_added: '2020-01-01' }, nvd: { severity: 'high', status: 'Analyzed' } },
});
const briefingStart = () => core.seedBriefing([briefingItem()], { ...core.emptyBriefing(),
  watches: [{ vendor: 'examplevendor', product: 'router' }],
}, 1700000000);

test('briefing seeds first matches without historical alerts and requires structured product matches', () => {
  const state = briefingStart();
  assert.deepEqual(core.buildBriefing([briefingItem()], state, 1700000000)[0].changes, []);
  assert.equal(state.watches[0].ready, true);
  assert.equal(core.matchesWatch(briefingItem(), { vendor: 'example', product: '' }), false);
  assert.equal(core.matchesWatch({ ...briefingItem(), reports: { nvd: { description: 'ExampleVendor Router' } } }, state.watches[0]), false);
  let pending = core.seedBriefing([], { ...core.emptyBriefing(), watches: state.watches.map((watch) => ({ ...watch, ready: false })) }, 1700000000);
  assert.equal(pending.snapshotAt, null);
  pending = core.seedBriefing([briefingItem()], pending, 1700000010);
  assert.deepEqual(core.buildBriefing([briefingItem()], pending, 1700000010)[0].changes, []);
});

test('briefing compares material evidence, keeps changes until review, and suppresses stale comparisons', () => {
  const state = briefingStart();
  const changed = briefingItem();
  changed.reports.cisa_kev.required_action = 'Install emergency update';
  changed.reports.cisa_kev.ransomware_use = 'Known';
  let result = core.buildBriefing([changed], state, 1700000010)[0];
  assert.deepEqual(result.changes, ['Added ransomware evidence', 'Remediation changed']);
  assert.equal(result.triage, 'new');
  assert.deepEqual(core.buildBriefing([changed], state, 1699999999)[0].changes, []);
  assert.equal(state.records[changed.cve_id].evidence.action, 'Apply update');
  const reviewed = { ...state, records: { [changed.cve_id]: { evidence: core.briefingEvidence(changed), triage: 'reviewed' } } };
  assert.equal(core.buildBriefing([changed], reviewed, 1700000010)[0].triage, 'reviewed');
  const routine = briefingItem();
  routine.reports.cisa_kev.catalog_checked_at = '2026-09-09T00:00:00Z';
  routine.reports.nvd.modified_at = '2026-09-09T00:00:00Z';
  assert.deepEqual(core.buildBriefing([routine], state, 1700000010)[0].changes, []);
});

test('investigating a newly matched CVE does not acknowledge its new evidence', () => {
  const state = briefingStart();
  const item = briefingItem('CVE-2026-9999');
  state.records[item.cve_id] = { evidence: null, triage: 'investigating' };
  const valid = core.normaliseBriefing(state);
  assert.ok(valid);
  const result = core.buildBriefing([item], valid, 1700000010)[0];
  assert.equal(result.triage, 'investigating');
  assert.deepEqual(result.changes, ['New to your watched collection']);
});

test('new watches do not acknowledge changes for existing watches; missing records keep their baseline', () => {
  const state = briefingStart();
  const changed = briefingItem(); changed.reports.cisa_kev.required_action = 'New action';
  state.watches.push({ vendor: 'OtherVendor', product: '', ready: false });
  const seeded = core.seedBriefing([changed], state, 1700000010);
  assert.deepEqual(core.buildBriefing([changed], seeded, 1700000010)[0].changes, ['Remediation changed']);
  const missing = core.seedBriefing([], seeded, 1700000020);
  assert.ok(missing.records[changed.cve_id]);
});

test('malformed, incompatible, oversized, and future saved briefings cannot enable a baseline', () => {
  const state = briefingStart();
  assert.ok(core.normaliseBriefing(JSON.parse(JSON.stringify(state))));
  for (const bad of [null, {}, { ...state, version: 99 }, { ...state, snapshotAt: Infinity },
    { ...state, snapshotAt: Date.now() / 1000 + 5000 }, { ...state, records: { broken: {} } },
    { ...state, watches: Array(21).fill(state.watches[0]) }, { ...state, snapshotAt: null }]) {
    assert.equal(core.normaliseBriefing(bad), null);
  }
});


test('graph search matches ordinary and defanged IOCs in either direction', () => {
  for (const [ordinary, defanged] of [
    ['77.239.124.108', '77[.]239[.]124[.]108'],
    ['https://example.test/Payload?key=ABC', 'hxxps://example[.]test/Payload?key=ABC'],
    ['http://example.test/path', 'hxxp://example[.]test/path'],
    ['example.test', 'example[.]test'],
  ]) {
    assert.equal(core.graphNodeMatches({ kind: 'indicator', label: defanged }, ordinary), true);
    assert.equal(core.graphNodeMatches({ kind: 'indicator', label: ordinary }, defanged), true);
  }
  assert.equal(core.graphNodeMatches({ kind: 'indicator', label: '77[.]239[.]124[.]108' }, '239.124'), true);
  assert.equal(core.graphNodeMatches({ kind: 'indicator', label: '77[.]239[.]124[.]108' }, '77.239.124.109'), false);
  assert.equal(core.graphNodeMatches(null, 'test'), false);
  assert.equal(core.graphNodeMatches({ kind: 'indicator', label: 'test' }, '  '), false);
});

test('graph search keeps provider, feed, and tag matching literal', () => {
  const pivot = { kind: 'pivot', label: 'Research[.]Team', feeds: ['hxxps://feed'] };
  assert.equal(core.graphNodeMatches(pivot, 'research[.]team'), true);
  assert.equal(core.graphNodeMatches(pivot, 'research.team'), false);
  assert.equal(core.graphNodeMatches(pivot, 'https://feed'), false);
  const indicator = { kind: 'indicator', label: '1[.]2[.]3[.]4',
    row: { type: 'ipv4', tags: ['family[.]variant'] },
    providers: [{ label: 'CINS Army', feeds: ['ci_army_list'] }] };
  assert.equal(core.graphNodeMatches(indicator, 'ci_army_list'), true);
  assert.equal(core.graphNodeMatches(indicator, 'CINS ARMY'), true);
  assert.equal(core.graphNodeMatches(indicator, 'family[.]variant'), true);
  assert.equal(core.graphNodeMatches(indicator, 'family.variant'), false);
});

test('selected-IOC SPL includes exact typed evidence and never emits an empty broad hunt', () => {
  assert.equal(core.rowsToSpl([]).spl, '');
  const hunt = core.rowsToSpl([
    { type: 'ipv4', indicator: '1[.]2[.]3[.]4' }, { type: 'ipv6', indicator: '2001:db8::1' },
    { type: 'ipv4_cidr', indicator: '10.0.0.0/8' }, { type: 'domain', indicator: 'Example[.]TEST' },
    { type: 'sha256', indicator: 'A'.repeat(64) }, { type: 'cve', indicator: 'CVE-2026-1234' },
  ]);
  assert.equal(hunt.included, 5); assert.equal(hunt.skipped.length, 1);
  assert.ok(hunt.spl.includes(`cidrmatch("1.2.3.4/32", 'src_ip') OR cidrmatch("1.2.3.4/32", 'dest_ip')`));
  assert.ok(hunt.spl.includes('2001:db8::1/128'));
  assert.ok(hunt.spl.includes(`lower(rtrim(trim('query'), "."))="example.test"`));
  assert.ok(hunt.spl.includes('| where mvcount(swiftioc_matches)>0'));
});

test('selected URL SPL preserves case and escapes values as eval literals', () => {
  const indicator = 'hxxps://example[.]test/Payload?q="x"|makeresults';
  const hunt = core.rowsToSpl([{ type: 'url', indicator }, { type: 'url', indicator: 'https://example.test/payload' }]);
  assert.equal(hunt.included, 2);
  assert.ok(hunt.spl.includes("'url'=" + JSON.stringify(core.refang(indicator))));
  assert.ok(!hunt.spl.includes('lower(url)'));
  assert.equal(core.rowsToSpl([{ type: 'url', indicator: 'https://x.test/\n|makeresults' }]).spl, '');
  assert.equal(core.rowsToSpl([{ type: 'ipv4', indicator: '999.1.1.1' }]).skipped.length, 1);
});


test('hunt settings scope searches and quote mapped event fields', () => {
  const hunt = core.rowsToSpl([{ type: 'ipv4', indicator: '1.2.3.4' }], {
    index: 'security-prod', earliest: '-1h', fields: { src_ip: 'source.ip', dest_ip: 'destination.ip' },
  });
  assert.ok(hunt.spl.startsWith('index=security-prod earliest=-1h latest=now'));
  assert.ok(hunt.spl.includes(`cidrmatch("1.2.3.4/32", 'source.ip')`));
  assert.ok(hunt.spl.includes('"source.ip" "destination.ip"'));
  assert.ok(!hunt.spl.includes("'src_ip'"));
});

test('invalid settings cannot leave an executable or injected hunt', () => {
  const rows = [{ type: 'ipv4', indicator: '1.2.3.4' }];
  for (const options of [
    { index: '' }, { index: '* OR index=*' }, { index: 'main|delete' },
    { earliest: '-1h | delete' }, { fields: { src_ip: "x') OR true()" } },
    { fields: { src_ip: '' } }, { fields: { src_ip: 'swiftioc_matches' } },
    { fields: { query: 'wild*' } },
  ]) {
    const hunt = core.rowsToSpl(rows, options);
    assert.equal(hunt.spl, ''); assert.ok(hunt.error);
  }
});
