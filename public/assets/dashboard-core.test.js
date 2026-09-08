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
    corroborated: 2,
    averageScore: 85,
    tagPivots: 1,
    sourcePivots: 0,
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
  assert.equal(graph.stats.pivots, 1);
  assert.equal(graph.stats.tagPivots, 1);
  assert.equal(graph.nodes.filter((node) => node.kind === 'pivot').length, 1);
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
  assert.match(html, /class="signal-radar"/);
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
