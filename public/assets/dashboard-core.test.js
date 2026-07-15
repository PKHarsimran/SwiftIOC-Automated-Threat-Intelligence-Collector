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

test('dashboard markup keeps IDs and labelled controls consistent', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
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
});
