(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.SwiftIOCCore = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  const stringValue = (value) => (value == null ? '' : String(value).trim());
  const lower = (value) => stringValue(value).toLowerCase();

  const refang = (value) =>
    stringValue(value)
      .replace(/hxxps:\/\//gi, 'https://')
      .replace(/hxxp:\/\//gi, 'http://')
      .replace(/\[\.\]/g, '.');

  const confidenceRank = (value) => {
    if (typeof value === 'number') {
      if (value >= 80) return 3;
      if (value >= 40) return 2;
      return value > 0 ? 1 : 0;
    }
    const text = lower(value);
    if (['critical', 'high', 'very-high'].includes(text)) return 3;
    if (['medium', 'moderate'].includes(text)) return 2;
    if (['low', 'info', 'informational'].includes(text)) return 1;
    return 0;
  };

  const effectiveScore = (row) => {
    if (typeof row?.score === 'number') return row.score;
    return [0, 40, 60, 80][confidenceRank(row?.confidence)] || 0;
  };

  const timestamp = (value) => {
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value > 1e12 ? value / 1000 : value;
    }
    const parsed = Date.parse(stringValue(value));
    return Number.isNaN(parsed) ? null : parsed / 1000;
  };

  const rowSources = (row) =>
    row?.sourceList?.length ? row.sourceList : [row?.source || 'unknown'];

  const selectedValues = (many, one) => {
    if (Array.isArray(many)) return many.filter(Boolean);
    return one && one !== 'all' ? [one] : [];
  };

  const scoreBand = (row) => {
    const score = effectiveScore(row);
    if (score >= 80) return 'high';
    if (score >= 60) return 'elevated';
    if (score >= 40) return 'moderate';
    return 'aging';
  };

  const ageBand = (row, nowSeconds) => {
    const seen = row.bestTimestamp ?? timestamp(row.lastSeen ?? row.firstSeen);
    if (seen == null) return 'unknown';
    const hours = (nowSeconds - seen) / 3600;
    if (hours < -5 / 60) return 'unknown';
    if (hours <= 24) return 'day';
    if (hours <= 168) return 'week';
    if (hours <= 720) return 'month';
    return 'older';
  };

  const matchesRow = (row, state, nowSeconds = Date.now() / 1000) => {
    if (!row) return false;
    const sourceCount = row.sourceCount || rowSources(row).length;

    if (state.signal === 'high' && effectiveScore(row) < 80) return false;
    if (state.signal === 'corroborated' && sourceCount < 2) return false;
    if (state.signal === 'new') {
      const firstSeen = timestamp(row.firstSeen);
      const age = firstSeen == null ? null : nowSeconds - firstSeen;
      if (age == null || age < -300 || age > 48 * 3600) return false;
    }

    const types = selectedValues(state.types, state.type);
    const sources = selectedValues(state.sources, state.source);
    const tags = selectedValues(state.tags, state.tag);
    if (types.length && !types.includes(lower(row.type))) return false;
    if (
      sources.length &&
      !rowSources(row).some((source) => sources.includes(lower(source)))
    ) return false;
    const rowTags = row.tagsLower || (row.tags || []).map(lower);
    if (tags.length && !rowTags.some((tag) => tags.includes(tag))) return false;

    const scoreBands = selectedValues(state.scoreBands);
    if (scoreBands.length && !scoreBands.includes(scoreBand(row))) return false;
    const ageBands = selectedValues(state.ageBands);
    if (ageBands.length && !ageBands.includes(ageBand(row, nowSeconds))) return false;
    if (effectiveScore(row) < (Number(state.minScore) || 0)) return false;

    if (state.age !== 'all') {
      const seen = row.bestTimestamp ?? timestamp(row.lastSeen ?? row.firstSeen);
      const age = seen == null ? null : nowSeconds - seen;
      if (age == null || age < -300 || age > Number(state.age) * 3600) {
        return false;
      }
    }

    const rawQuery = lower(state.search);
    const refangedQuery = lower(refang(state.search));
    if (rawQuery || refangedQuery) {
      const haystack = [
        row.indicator,
        row.type,
        ...rowSources(row),
        ...(row.tags || []),
        row.context,
      ].filter(Boolean).join(' ').toLowerCase();
      if (
        !haystack.includes(rawQuery) &&
        !refang(haystack).toLowerCase().includes(refangedQuery)
      ) return false;
    }
    return true;
  };

  const compareRows = (a, b, state) => {
    let left;
    let right;
    if (state.sort === 'indicator') {
      left = lower(a.indicator);
      right = lower(b.indicator);
    } else if (state.sort === 'type') {
      left = lower(a.type);
      right = lower(b.type);
    } else if (state.sort === 'sources') {
      left = a.sourceCount || rowSources(a).length;
      right = b.sourceCount || rowSources(b).length;
    } else if (state.sort === 'lastSeen') {
      left = a.bestTimestamp ?? timestamp(a.lastSeen) ?? -Infinity;
      right = b.bestTimestamp ?? timestamp(b.lastSeen) ?? -Infinity;
    } else {
      left = effectiveScore(a);
      right = effectiveScore(b);
    }

    let result = typeof left === 'string'
      ? left.localeCompare(String(right))
      : left - right;
    if (state.direction === 'desc') result *= -1;
    if (result) return result;

    const sourceDifference =
      (b.sourceCount || rowSources(b).length) -
      (a.sourceCount || rowSources(a).length);
    return sourceDifference || lower(a.indicator).localeCompare(lower(b.indicator));
  };

  const readViewState = (search = '', hash = '') => {
    const params = new URLSearchParams(search);
    const signal = params.get('signal');
    const score = Number(params.get('score')) || 0;
    const age = params.get('age') || 'all';
    const state = {
      types: params.getAll('type').filter(Boolean),
      sources: params.getAll('source').filter(Boolean),
      tags: params.getAll('tag').filter(Boolean),
      scoreBands: params.getAll('score_band').filter((value) =>
        ['high', 'elevated', 'moderate', 'aging'].includes(value)
      ),
      ageBands: params.getAll('age_band').filter((value) =>
        ['day', 'week', 'month', 'older', 'unknown'].includes(value)
      ),
      type: params.get('type') || 'all',
      source: params.get('source') || 'all',
      tag: params.get('tag') || 'all',
      signal: ['all', 'high', 'corroborated', 'new'].includes(signal)
        ? signal
        : 'all',
      minScore: [0, 40, 60, 80].includes(score) ? score : 0,
      age: ['all', '24', '48', '168', '720'].includes(age) ? age : 'all',
      limit: [12, 25, 50, 100].includes(Number(params.get('rows')))
        ? Number(params.get('rows'))
        : 12,
      sort: ['indicator', 'type', 'score', 'sources', 'lastSeen'].includes(
        params.get('sort')
      ) ? params.get('sort') : 'score',
      direction: params.get('dir') === 'asc' ? 'asc' : 'desc',
      search: '',
    };
    if (hash.startsWith('#view=')) {
      try {
        const shared = JSON.parse(decodeURIComponent(hash.slice(6)));
        if (typeof shared?.q === 'string') state.search = shared.q;
      } catch (error) {
        // Invalid fragments are intentionally ignored.
      }
    }
    return state;
  };

  const writeViewUrl = (currentUrl, state, includeSearch = false) => {
    const url = new URL(currentUrl);
    ['type', 'source', 'tag', 'score_band', 'age_band', 'signal', 'score', 'age', 'rows', 'sort', 'dir']
      .forEach((key) => url.searchParams.delete(key));
    selectedValues(state.types, state.type).forEach((value) =>
      url.searchParams.append('type', value)
    );
    selectedValues(state.sources, state.source).forEach((value) =>
      url.searchParams.append('source', value)
    );
    selectedValues(state.tags, state.tag).forEach((value) =>
      url.searchParams.append('tag', value)
    );
    selectedValues(state.scoreBands).forEach((value) =>
      url.searchParams.append('score_band', value)
    );
    selectedValues(state.ageBands).forEach((value) =>
      url.searchParams.append('age_band', value)
    );
    if (state.signal !== 'all') url.searchParams.set('signal', state.signal);
    if (state.minScore) url.searchParams.set('score', String(state.minScore));
    if (state.age !== 'all') url.searchParams.set('age', state.age);
    if (state.limit !== 12) url.searchParams.set('rows', String(state.limit));
    if (state.sort !== 'score') url.searchParams.set('sort', state.sort);
    if (state.direction !== 'desc') url.searchParams.set('dir', state.direction);
    if (includeSearch && state.search) {
      url.hash = 'view=' + encodeURIComponent(JSON.stringify({ q: state.search }));
    } else if (url.hash.startsWith('#view=')) {
      url.hash = '';
    }
    return url;
  };

  return {
    compareRows,
    effectiveScore,
    matchesRow,
    readViewState,
    refang,
    writeViewUrl,
  };
});
