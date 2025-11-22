(function () {
  'use strict';

  /* ==========================================================================
   *  CONFIG & CONSTANTS
   * ========================================================================= */

  const resolveIocUrl = (path) => {
    const base = document.body?.dataset.iocRoot || './';
    return new URL(path, new URL(base, window.location.href)).toString();
  };

  const DEFAULT_PREVIEW_LIMIT = 12;
  const PREVIEW_LOOKAHEAD_MULTIPLIER = 12;
  const PREVIEW_CACHE_LIMIT = Math.max(
    DEFAULT_PREVIEW_LIMIT * PREVIEW_LOOKAHEAD_MULTIPLIER,
    240
  );

  const INDICATORS_JSONL_URL = resolveIocUrl('iocs/latest.jsonl');
  const INDICATORS_JSON_FALLBACK_URL = resolveIocUrl('iocs/latest.json');
  const PREVIEW_STREAM_URL = INDICATORS_JSONL_URL;

  const DATASET_STORAGE_KEY = 'swiftioc-dashboard-cache-v1';
  const DATASET_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  const numberFormatter = new Intl.NumberFormat('en-US');
  const formatNumber = (value) => numberFormatter.format(value ?? 0);

  const relativeTimeFormatter =
    typeof Intl !== 'undefined' &&
    typeof Intl.RelativeTimeFormat === 'function'
      ? new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
      : null;

  const dateTimeFormatter =
    typeof Intl !== 'undefined' && typeof Intl.DateTimeFormat === 'function'
      ? new Intl.DateTimeFormat('en-CA', {
          dateStyle: 'medium',
          timeStyle: 'short',
        })
      : null;

  const dateFormatter =
    typeof Intl !== 'undefined' && typeof Intl.DateTimeFormat === 'function'
      ? new Intl.DateTimeFormat('en-CA', {
          dateStyle: 'medium',
        })
      : null;

  const timeFormatter =
    typeof Intl !== 'undefined' && typeof Intl.DateTimeFormat === 'function'
      ? new Intl.DateTimeFormat('en-CA', {
          timeStyle: 'short',
        })
      : null;

  /* ==========================================================================
   *  DOM HELPERS
   * ========================================================================= */

  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

  const setText = (el, value) => {
    if (!el) return;
    el.textContent = value ?? '';
  };

  const setStatText = (name, value) => {
    qsa(`[data-stat="${name}"]`).forEach((el) => {
      setText(el, value);
    });
  };

  const normaliseString = (value) => {
    if (value == null) return '';
    if (typeof value === 'string') return value.trim();
    return String(value).trim();
  };

  const normaliseLower = (value) => normaliseString(value).toLowerCase();

  const coalesceString = (...values) => {
    for (const v of values) {
      const s = normaliseString(v);
      if (s) return s;
    }
    return '';
  };

  const uniqueStrings = (values) => {
    const seen = new Set();
    const result = [];
    for (const value of values || []) {
      const s = normaliseString(value);
      if (!s) continue;
      const key = s.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      result.push(s);
    }
    return result;
  };

  const clamp = (value, min, max) =>
    Math.min(max, Math.max(min, value));

  const parseTimestamp = (value) => {
    if (value == null) return null;

    if (typeof value === 'number') {
      const time =
        value > 1e12 && value < 1e13 ? Math.round(value / 1000) : value;
      const date = new Date(time * 1000);
      if (Number.isNaN(date.getTime())) return null;
      return {
        time,
        iso: date.toISOString(),
      };
    }

    const string = normaliseString(value);
    if (!string) return null;

    const numeric = Number(string);
    if (!Number.isNaN(numeric)) {
      return parseTimestamp(numeric);
    }

    // Try to parse ISO-ish strings
    const parsed = Date.parse(string);
    if (Number.isNaN(parsed)) return null;

    const time = Math.round(parsed / 1000);
    return {
      time,
      iso: new Date(time * 1000).toISOString(),
    };
  };

  const isoToParts = (isoString) => {
    if (!isoString || typeof isoString !== 'string') {
      return { date: null, time: null };
    }
    const [datePart, timePart] = isoString.split('T');
    const time = timePart ? timePart.slice(0, 8) : null;
    return { date: datePart || null, time };
  };

  const formatRelativeTimeFromNow = (timestamp) => {
    if (!relativeTimeFormatter || typeof timestamp !== 'number') {
      return null;
    }

    const now = Date.now();
    const diff = timestamp * 1000 - now;
    const absDiff = Math.abs(diff);

    const minute = 60 * 1000;
    const hour = 60 * minute;
    const day = 24 * hour;
    const week = 7 * day;
    const month = 30 * day;
    const year = 365 * day;

    const divisions = [
      { amount: 60, unit: 'seconds' },
      { amount: 60, unit: 'minutes' },
      { amount: 24, unit: 'hours' },
      { amount: 7, unit: 'days' },
      { amount: 4.34524, unit: 'weeks' },
      { amount: 12, unit: 'months' },
      { amount: Infinity, unit: 'years' },
    ];

    let delta = Math.round(diff / 1000);
    for (const division of divisions) {
      if (Math.abs(delta) < division.amount || division.amount === Infinity) {
        return relativeTimeFormatter.format(delta, division.unit);
      }
      delta = Math.round(delta / division.amount);
    }
    return null;
  };

  const formatAbsoluteTimestamp = (timestamp) => {
    if (typeof timestamp !== 'number') return null;
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return null;
    if (dateTimeFormatter) return dateTimeFormatter.format(date);
    return date.toISOString();
  };

  const formatTimestampForDisplay = (value) => {
    const parsed = parseTimestamp(value);
    if (!parsed) {
      const fallback = normaliseString(value);
      return fallback || '—';
    }
    const absolute = formatAbsoluteTimestamp(parsed.time);
    if (absolute) return absolute;
    const parts = isoToParts(parsed.iso);
    if (parts.date && parts.time) return `${parts.date} ${parts.time}`;
    if (parts.date) return parts.date;
    return parsed.iso;
  };

  const formatDateParts = (value) => {
    const parsed = parseTimestamp(value);
    if (!parsed) {
      return {
        date: '—',
        time: '—',
        relative: '—',
      };
    }

    const date = new Date(parsed.time * 1000);
    const dateLabel = dateFormatter
      ? dateFormatter.format(date)
      : isoToParts(parsed.iso).date ?? parsed.iso;
    const timeLabel = timeFormatter
      ? timeFormatter.format(date)
      : isoToParts(parsed.iso).time ?? '';

    const relativeLabel = formatRelativeTimeFromNow(parsed.time) ?? '—';

    return {
      date: dateLabel,
      time: timeLabel,
      relative: relativeLabel,
    };
  };

  const formatDatePartsFromSeconds = (seconds) => {
    if (typeof seconds !== 'number') return null;
    return formatDateParts(seconds * 1000);
  };

  const formatDateTimeLabel = (parts) => {
    if (!parts) return '—';
    const date = normaliseString(parts.date);
    const time = normaliseString(parts.time);
    if (date && time) return `${date} ${time}`;
    if (date) return date;
    if (time) return time;
    return '—';
  };

  /* ==========================================================================
   *  CONFIDENCE
   * ========================================================================= */

  const confidenceRankForValue = (value) => {
    if (value == null) return 0;

    if (typeof value === 'string') {
      const lower = value.toLowerCase().trim();
      if (!lower) return 0;
      if (['high', 'critical', 'very-high'].includes(lower)) return 3;
      if (['medium', 'moderate'].includes(lower)) return 2;
      if (['low', 'info', 'informational'].includes(lower)) return 1;

      const numeric = Number(lower.replace(/[^\d.]+/g, ''));
      if (!Number.isNaN(numeric)) {
        if (numeric >= 80) return 3;
        if (numeric >= 40) return 2;
        if (numeric > 0) return 1;
      }
      return 0;
    }

    if (typeof value === 'number') {
      const numeric = clamp(value, 0, 100);
      if (numeric >= 80) return 3;
      if (numeric >= 40) return 2;
      if (numeric > 0) return 1;
      return 0;
    }

    return 0;
  };

  const confidenceRankForRow = (row) => {
    if (!row) return 0;
    if (typeof row.confidenceRank === 'number') return row.confidenceRank;
    const rank = confidenceRankForValue(row.confidenceLower || row.confidence);
    row.confidenceRank = rank;
    return rank;
  };

  const confidenceClassFor = (confidence) => {
    const rank = confidenceRankForValue(confidence);
    if (rank >= 3) return 'confidence-high';
    if (rank === 2) return 'confidence-medium';
    if (rank === 1) return 'confidence-low';
    return null;
  };

  /* ==========================================================================
   *  TAGS
   * ========================================================================= */

  const extractTags = (value) => {
    if (!value) return [];
    if (Array.isArray(value)) return uniqueStrings(value);
    if (typeof value === 'string') return uniqueStrings(value.split(/[,;\|]/));
    if (typeof value === 'object') return uniqueStrings(Object.values(value));
    return [];
  };

  /* ==========================================================================
   *  STAT ACCUMULATORS
   * ========================================================================= */

  const createStatsAccumulator = () => {
    let total = 0;
    let duplicatesRemoved = 0;
    const sources = new Set();
    const types = new Set();
    const tags = new Map();

    let earliestFirstSeen = null;
    let newestFirstSeen = null;
    let earliestLastSeen = null;
    let newestLastSeen = null;

    const registerFirstSeen = (value) => {
      const parsed = parseTimestamp(value);
      if (!parsed) return;
      const time = parsed.time;
      if (!earliestFirstSeen || time < earliestFirstSeen) {
        earliestFirstSeen = time;
      }
      if (!newestFirstSeen || time > newestFirstSeen) {
        newestFirstSeen = time;
      }
    };

    const registerLastSeen = (value) => {
      const parsed = parseTimestamp(value);
      if (!parsed) return;
      const time = parsed.time;
      if (!earliestLastSeen || time < earliestLastSeen) {
        earliestLastSeen = time;
      }
      if (!newestLastSeen || time > newestLastSeen) {
        newestLastSeen = time;
      }
    };

    const ingest = (row) => {
      if (!row || typeof row !== 'object') return;

      total += 1;

      const source = normaliseString(row.source);
      const type = normaliseString(row.type);
      const indicator = normaliseString(row.indicator);

      if (source) {
        sources.add(source);
      }

      if (type) {
        types.add(type);
      }

      if (indicator && row.isDuplicate) {
        duplicatesRemoved += 1;
      }

      registerFirstSeen(row.firstSeen || row.first_seen);
      registerLastSeen(row.lastSeen || row.last_seen);

      const combinedTags = uniqueStrings([
        ...extractTags(row?.tags),
        ...extractTags(row?.labels),
        ...extractTags(row?.label),
        ...extractTags(row?.classifications),
        ...extractTags(row?.malware_family),
      ]);

      combinedTags.forEach((tag) => {
        tags.set(tag, (tags.get(tag) || 0) + 1);
      });
    };

    const finalise = () => {
      const earliestFirstSeenParts =
        formatDatePartsFromSeconds(earliestFirstSeen) || {
          date: '—',
          time: '—',
          relative: '—',
        };

      const newestFirstSeenParts =
        formatDatePartsFromSeconds(newestFirstSeen) || {
          date: '—',
          time: '—',
          relative: '—',
        };

      const earliestLastSeenParts = formatDatePartsFromSeconds(earliestLastSeen);
      const newestLastSeenParts = formatDatePartsFromSeconds(newestLastSeen);

      let collectionWindow = '—';
      const windowStart = earliestFirstSeen || earliestLastSeen;
      const windowEnd = newestLastSeen || newestFirstSeen;
      if (windowStart && windowEnd) {
        const startLabel = dateFormatter
          ? dateFormatter.format(new Date(windowStart * 1000))
          : formatDateTimeLabel(
              formatDatePartsFromSeconds(windowStart) ||
                formatDateParts(windowStart * 1000)
            );
        const endLabel = dateFormatter
          ? dateFormatter.format(new Date(windowEnd * 1000))
          : formatDateTimeLabel(
              formatDatePartsFromSeconds(windowEnd) ||
                formatDateParts(windowEnd * 1000)
            );
        collectionWindow = `${startLabel} → ${endLabel}`;
      }

      return {
        total,
        duplicatesRemoved,
        activeSources: sources.size,
        indicatorTypes: types.size,
        tags,
        earliestFirstSeen: earliestFirstSeenParts,
        newestFirstSeen: newestFirstSeenParts,
        earliestLastSeen: earliestLastSeenParts,
        newestLastSeen: newestLastSeenParts,
        earliestFirstSeenTs: earliestFirstSeen,
        newestFirstSeenTs: newestFirstSeen,
        earliestLastSeenTs: earliestLastSeen,
        newestLastSeenTs: newestLastSeen,
        collectionWindow,
      };
    };

    return {
      ingest,
      finalise,
    };
  };

  const createTableAggregators = () => {
    const bySource = new Map();
    const byType = new Map();
    const tags = new Map();

    const ingest = (row) => {
      if (!row || typeof row !== 'object') return;

      const source = normaliseString(row.source);
      const type = normaliseString(row.type);

      if (source) {
        bySource.set(source, (bySource.get(source) || 0) + 1);
      }

      if (type) {
        byType.set(type, (byType.get(type) || 0) + 1);
      }

      const combinedTags = uniqueStrings([
        ...extractTags(row?.tags),
        ...extractTags(row?.labels),
        ...extractTags(row?.label),
        ...extractTags(row?.classifications),
        ...extractTags(row?.malware_family),
      ]);

      combinedTags.forEach((tag) => {
        tags.set(tag, (tags.get(tag) || 0) + 1);
      });
    };

    const toRows = (map, labelKey) => {
      const entries = Array.from(map.entries());
      const total = entries.reduce((sum, [, count]) => sum + count, 0) || 1;

      return entries
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([label, count]) => {
          const share = `${((count / total) * 100).toFixed(1)}%`;
          return [
            {
              title: labelKey,
              value: label,
            },
            {
              title: 'Count',
              value: formatNumber(count),
              numeric: true,
            },
            {
              title: 'Share',
              value: share,
              numeric: true,
            },
          ];
        });
    };

    const toTagRows = () =>
      toRows(tags, 'Tag');

    return {
      ingest,
      toSourceRows: () => toRows(bySource, 'Source'),
      toTypeRows: () => toRows(byType, 'Type'),
      toTagRows,
    };
  };

  /* ==========================================================================
   *  TABLE POPULATION
   * ========================================================================= */

  const getTableTargets = (name) =>
    qsa(`[data-table="${name}"]`, document);

  const populateTable = (name, rows, emptyMessage) => {
    getTableTargets(name).forEach((tbody) => {
      if (!tbody) return;
      tbody.innerHTML = '';

      if (!rows.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        const columnCount =
          tbody.closest('table')?.querySelectorAll('thead th').length ?? 1;
        td.setAttribute('colspan', columnCount);
        td.textContent = emptyMessage;
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }

      rows.forEach((cells) => {
        const tr = document.createElement('tr');
        cells.forEach((cell) => {
          const td = document.createElement('td');
          td.dataset.title = cell.title;
          if (cell.numeric) td.classList.add('numeric');
          td.textContent = cell.value;
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    });
  };

  /* ==========================================================================
   *  JSON/JSONL PARSING
   * ========================================================================= */

  const parseJsonSafely = (line) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      console.warn('Unable to parse JSON line', error);
      return null;
    }
  };

  const streamJsonLines = async (url, previewLimit) => {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/jsonl, application/x-ndjson, application/json, text/plain',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to load indicators: ${response.status} ${response.statusText}`);
    }

    if (!response.body || typeof response.body.getReader !== 'function') {
      // Fallback: not a stream, just parse as text
      const text = await response.text();
      const lines = text.split(/\r?\n/).filter(Boolean);
      const entries = [];
      for (const line of lines) {
        const parsed = parseJsonSafely(line);
        if (parsed) entries.push(parsed);
      }
      return { entries, previewEntries: entries.slice(0, previewLimit) };
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');

    let buffer = '';
    const entries = [];
    const previewEntries = [];

    const tryPushPreview = (row) => {
      if (previewEntries.length >= previewLimit) return;
      previewEntries.push(row);
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let newlineIndex;
      while ((newlineIndex = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newlineIndex).trim();
        buffer = buffer.slice(newlineIndex + 1);
        if (!line) continue;

        const parsed = parseJsonSafely(line);
        if (!parsed) continue;

        entries.push(parsed);
        tryPushPreview(parsed);
      }
    }

    buffer = buffer.trim();
    if (buffer) {
      const parsed = parseJsonSafely(buffer);
      if (parsed) {
        entries.push(parsed);
        tryPushPreview(parsed);
      }
    }

    return { entries, previewEntries };
  };

  /* ==========================================================================
   *  NORMALISATION
   * ========================================================================= */

  const normaliseRow = (row) => {
    if (!row || typeof row !== 'object') return null;

    const indicator = coalesceString(
      row.indicator,
      row.value,
      row.ioc,
      row.indicator_value,
      row.observable,
      row.observable_value,
      row.ip,
      row.ipv4,
      row.ipv6,
      row.domain,
      row.hostname,
      row.url,
      row.uri,
      row.hash,
      row.sha256,
      row.sha1,
      row.md5
    );

    if (!indicator) return null;

    const typeRaw = coalesceString(
      row.type,
      row.indicator_type,
      row.indicatorType,
      row.observable_type,
      row.observableType,
      row.pattern_type,
      row.kind,
      row.category
    );
    const sourceRaw = coalesceString(
      row.source,
      row.feed,
      row.provider,
      row.collection,
      row.origin,
      row.dataset,
      row.author,
      row.organization
    );

    const confidenceRaw = coalesceString(
      row.confidence,
      row.confidence_score,
      row.confidenceScore,
      row.confidence_level,
      row.confidenceLevel,
      row.score
    );

    const tagValues = [
      ...extractTags(row.tags),
      ...extractTags(row.labels),
      ...extractTags(row.label),
      ...extractTags(row.classifications),
      ...extractTags(row.malware_family),
      ...extractTags(row.threat_type),
      ...extractTags(row.threat_types),
    ];

    const tags = uniqueStrings(tagValues);
    const tagsLower = tags.map((tag) => tag.toLowerCase());

    const firstSeen =
      row.first_seen ??
      row.firstSeen ??
      row.first_observed ??
      row.firstSeenAt ??
      row.created_at ??
      row.created;

    const lastSeen =
      row.last_seen ??
      row.lastSeen ??
      row.last_observed ??
      row.lastSeenAt ??
      row.updated_at ??
      row.modified;

    const confidence = confidenceRaw || null;

    const normalised = {
      indicator,
      type: typeRaw || 'unknown',
      source: sourceRaw || 'unknown',
      confidence,
      confidenceRank: confidenceRankForValue(confidence),
      tags,
      tagsLower,
      firstSeen,
      lastSeen,
      isDuplicate: Boolean(row.is_duplicate || row.duplicate),
      raw: row,
    };

    return normalised;
  };

  /* ==========================================================================
   *  DATASET FETCH + NOTIFICATION
   * ========================================================================= */

  const datasetListeners = new Set();
  const subscribeToDataset = (listener) => {
    if (typeof listener !== 'function') return () => {};
    datasetListeners.add(listener);
    return () => datasetListeners.delete(listener);
  };

  const isCacheOrigin = (origin) =>
    origin === 'cache' || origin === 'cache-stale';

  const notifyDatasetListeners = (dataset) => {
    if (!dataset || isCacheOrigin(dataset.origin)) return;
    datasetListeners.forEach((listener) => {
      try {
        listener(dataset);
      } catch (error) {
        console.error('Dataset listener failed', error);
      }
    });
  };

  const datasetCache = {
    promise: null,
    refreshing: null,
  };

  const loadFromStorage = () => {
    try {
      const raw = localStorage.getItem(DATASET_STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      const { entries, fetchedAt, stats } = parsed;
      if (!Array.isArray(entries) || typeof fetchedAt !== 'number') {
        return null;
      }
      const age = Date.now() - fetchedAt;
      if (age > DATASET_CACHE_TTL * 4) {
        return null;
      }
      return {
        origin: age > DATASET_CACHE_TTL ? 'cache-stale' : 'cache',
        entries,
        stats,
        fetchedAt,
      };
    } catch (error) {
      console.warn('Failed to load cache', error);
      return null;
    }
  };

  const saveToStorage = (dataset) => {
    try {
      const { entries, stats, fetchedAt } = dataset;
      if (!Array.isArray(entries)) return;
      localStorage.setItem(
        DATASET_STORAGE_KEY,
        JSON.stringify({
          entries,
          stats,
          fetchedAt: fetchedAt ?? Date.now(),
        })
      );
    } catch (error) {
      console.warn('Failed to persist cache', error);
    }
  };

  const fetchJsonDataset = async (url, previewLimit) => {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json, text/plain',
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to load indicators: ${response.status} ${response.statusText}`);
    }

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (error) {
      console.warn('Failed to parse indicators JSON', error);
      data = [];
    }

    const entries = Array.isArray(data) ? data : data.entries || [];
    const previewEntries = entries.slice(0, previewLimit);
    return { entries, previewEntries };
  };

  const fetchDataset = async (previewLimit) => {
    try {
      return await streamJsonLines(PREVIEW_STREAM_URL, previewLimit);
    } catch (error) {
      console.warn('JSONL request failed, falling back to JSON', error);
      return fetchJsonDataset(INDICATORS_JSON_FALLBACK_URL, previewLimit);
    }
  };

  const resolveDataset = async ({ forceRefresh = false } = {}) => {
    const wrapDatasetPromise = (promise) =>
      promise.then((dataset) => {
        notifyDatasetListeners(dataset);
        return dataset;
      });

    const fetchFreshDataset = async () => {
      const { entries, previewEntries } = await fetchDataset(PREVIEW_CACHE_LIMIT);

      const statsAccumulator = createStatsAccumulator();
      const tableAggregators = createTableAggregators();

      const normalisedEntries = [];
      for (const row of entries) {
        const normalised = normaliseRow(row);
        if (!normalised) continue;
        statsAccumulator.ingest(normalised);
        tableAggregators.ingest(normalised);
        normalisedEntries.push(normalised);
      }

      const stats = statsAccumulator.finalise();

      const previewEntriesNormalised = [];
      for (const row of previewEntries) {
        const normalised = normaliseRow(row);
        if (!normalised) continue;
        previewEntriesNormalised.push(normalised);
      }

      const dataset = {
        origin: 'network',
        entries: normalisedEntries,
        previewEntries: previewEntriesNormalised,
        stats,
        fetchedAt: Date.now(),
        sourcesTable: tableAggregators.toSourceRows(),
        typesTable: tableAggregators.toTypeRows(),
        tagsTable: tableAggregators.toTagRows(),
      };

      saveToStorage(dataset);
      return dataset;
    };

    // If there's a cache hit and we're not forcing a refresh, return cache first
    if (!forceRefresh) {
      const cached = loadFromStorage();
      if (cached && !datasetCache.promise) {
        const statsAccumulator = createStatsAccumulator();
        const tableAggregators = createTableAggregators();

        const normalisedEntries = [];
        for (const row of cached.entries || []) {
          const normalised = normaliseRow(row);
          if (!normalised) continue;
          statsAccumulator.ingest(normalised);
          tableAggregators.ingest(normalised);
          normalisedEntries.push(normalised);
        }

        const stats = cached.stats || statsAccumulator.finalise();
        const dataset = {
          origin: cached.origin,
          entries: normalisedEntries,
          previewEntries: normalisedEntries.slice(0, PREVIEW_CACHE_LIMIT),
          stats,
          fetchedAt: cached.fetchedAt,
          sourcesTable: tableAggregators.toSourceRows(),
          typesTable: tableAggregators.toTypeRows(),
          tagsTable: tableAggregators.toTagRows(),
        };

        datasetCache.promise = Promise.resolve(dataset);
        return dataset;
      }
    }

    if (!datasetCache.promise) {
      datasetCache.promise = wrapDatasetPromise(fetchFreshDataset());
    }

    const resolved = await datasetCache.promise;

    if (!isCacheOrigin(resolved.origin) && !datasetCache.refreshing) {
      const refresh = fetchFreshDataset()
        .then((fresh) => {
          datasetCache.promise = Promise.resolve(fresh);
          notifyDatasetListeners(fresh);
          return fresh;
        })
        .catch((error) => {
          console.warn('Background refresh failed', error);
          return null;
        })
        .finally(() => {
          if (datasetCache.refreshing === refresh) {
            datasetCache.refreshing = null;
          }
        });

      datasetCache.refreshing = refresh;
    }

    return resolved;
  };

  const loadDataset = async ({
    previewLimit = DEFAULT_PREVIEW_LIMIT,
    forceRefresh = false,
  } = {}) => {
    const dataset = await resolveDataset({ forceRefresh });

    const previewEntries = dataset.previewEntries || [];
    const previewRows = previewEntries.slice(0, previewLimit);

    return {
      dataset,
      previewRows,
    };
  };

  /* ==========================================================================
   *  GLOBAL STATS + TABLES
   * ========================================================================= */

  const applyStats = (stats, dataset) => {
    if (!stats) return;

    const fetchedLabel =
      dataset?.fetchedAt != null
        ? formatTimestampForDisplay(dataset.fetchedAt / 1000)
        : null;

    const generatedLabel = formatDateTimeLabel(
      stats.newestFirstSeen || stats.newestLastSeen
    );

    const generatedStat =
      generatedLabel !== '—' ? generatedLabel : fetchedLabel || '—';
    setStatText('generated-at', generatedStat);

    setStatText('total-indicators', formatNumber(stats.total));
    setStatText('duplicates-removed', formatNumber(stats.duplicatesRemoved));
    setStatText('active-sources', formatNumber(stats.activeSources));
    setStatText('indicator-types', formatNumber(stats.indicatorTypes));

    const feedsText =
      stats.activeSources != null
        ? `${formatNumber(stats.activeSources)} active source${
            stats.activeSources === 1 ? '' : 's'
          }`
        : '—';
    setStatText('feeds-online', feedsText);

    setStatText('collection-window', stats.collectionWindow ?? '—');

    if (stats.earliestFirstSeen) {
      setStatText(
        'earliest-first-seen-date',
        stats.earliestFirstSeen.date ?? '—'
      );
      setStatText(
        'earliest-first-seen-time',
        stats.earliestFirstSeen.time ?? '—'
      );
      setStatText(
        'earliest-first-seen-relative',
        stats.earliestFirstSeen.relative ?? '—'
      );
    }

    if (stats.newestFirstSeen) {
      setStatText(
        'newest-first-seen-date',
        stats.newestFirstSeen.date ?? '—'
      );
      setStatText(
        'newest-first-seen-time',
        stats.newestFirstSeen.time ?? '—'
      );
      setStatText(
        'newest-first-seen-relative',
        stats.newestFirstSeen.relative ?? '—'
      );
    }

    if (stats.sourcesTable) {
      populateTable(
        'sources',
        stats.sourcesTable,
        'No active sources in this run.'
      );
    }

    if (stats.typesTable) {
      populateTable(
        'types',
        stats.typesTable,
        'No indicator types could be derived.'
      );
    }

    if (stats.tagsTable) {
      populateTable(
        'tags',
        stats.tagsTable,
        'No tags were present across indicators.'
      );
    }
  };

  /* ==========================================================================
   *  STATUS BANNER INITIALISATION
   * ========================================================================= */

  const initialiseStatusBanner = () => {
    const root = qs('[data-site-status-root]');
    if (!root) return;

    const labelEl = qs('[data-site-status-label]', root);
    const generatedEl = qs('[data-site-generated]', root);
    const updatedEl = qs('[data-site-updated]', root);
    const windowEl = qs('[data-site-window]', root);

    const updateFromStats = (stats, dataset) => {
      if (!stats || !dataset) return;

      const state = dataset.origin;
      root.dataset.state = state;

      const originLabel =
        state === 'live' || state === 'network'
          ? 'Live from collector'
          : state === 'cache'
          ? 'Cached (fresh)'
          : state === 'cache-stale'
          ? 'Cached (stale)'
          : 'Unknown origin';

      if (labelEl) {
        labelEl.textContent = originLabel;
      }

      const generatedLabel = formatDateTimeLabel(
        stats.newestFirstSeen || stats.newestLastSeen
      );
      const updatedLabel = formatDateTimeLabel(
        stats.newestLastSeen || stats.newestFirstSeen
      );

      const timestampFallback = formatTimestampForDisplay(
        (dataset.fetchedAt != null ? dataset.fetchedAt : Date.now()) / 1000
      );

      if (generatedEl) {
        generatedEl.textContent = generatedLabel !== '—'
          ? generatedLabel
          : timestampFallback;
      }

      if (updatedEl) {
        updatedEl.textContent = updatedLabel !== '—'
          ? updatedLabel
          : timestampFallback;
      }

      if (windowEl) {
        windowEl.textContent = stats.collectionWindow ?? '—';
      }
    };

    subscribeToDataset((dataset) => {
      if (!dataset || !dataset.stats) return;
      const origin =
        dataset.origin === 'network'
          ? 'live'
          : isCacheOrigin(dataset.origin)
          ? dataset.origin
          : 'live';

      dataset.origin = origin;
      updateFromStats(dataset.stats, dataset);
    });
  };

  const loadStats = async () => {
    try {
      const { dataset } = await loadDataset({
        previewLimit: DEFAULT_PREVIEW_LIMIT,
      });
      applyStats(dataset.stats, dataset);
    } catch (error) {
      console.error('Unable to load initial stats', error);
    }
  };

  /* ==========================================================================
   *  LIVE PREVIEW
   * ========================================================================= */

  const initialisePreview = () => {
    const container = qs('[data-preview-container]');
    if (!container) return;

    const table = qs('[data-preview-table]', container);
    const tbody = qs('[data-preview-body]', container);
    const statusEl = qs('[data-preview-status]', container);

    const filterSelect = qs('[data-preview-filter]', container);
    const tagFilterSelect = qs('[data-preview-tag-filter]', container);
    const limitSelect = qs('[data-preview-limit]', container);
    const searchInput = qs('[data-preview-search]', container);
    const refreshButton = qs('[data-preview-refresh]', container);

    const summaryRoot = qs('[data-preview-summary]', container);
    const summaryVisibleEl = qs('[data-preview-visible]', container);
    const summaryTotalEl = qs('[data-preview-total]', container);
    const summaryHighEl = qs('[data-preview-high]', container);
    const summaryHighPercentEl = qs(
      '[data-preview-high-percent]',
      container
    );
    const summaryTopTagEl = qs('[data-preview-top-tag]', container);
    const summaryTopTagCountEl = qs(
      '[data-preview-top-tag-count]',
      container
    );
    const summaryPoolEl = qs('[data-preview-pool]', container);

    const metaRoot = qs('[data-preview-meta]', container);
    const metaOriginEl = qs('[data-preview-origin]', container);
    const metaRefreshedEl = qs('[data-preview-refreshed]', container);
    const metaRelativeEl = qs('[data-preview-relative]', container);

    const state = {
      rows: [],
      filter: 'all',
      tagFilter: 'all',
      search: '',
      limit: DEFAULT_PREVIEW_LIMIT,
      origin: 'network',
      fetchedAt: null,
      stats: null,
      previewPool: 0,
      loading: false,
    };

    if (limitSelect) {
      const initialLimit = parseInt(limitSelect.value, 10);
      if (!Number.isNaN(initialLimit) && initialLimit > 0) {
        state.limit = initialLimit;
      } else {
        limitSelect.value = String(state.limit);
      }
    }

    const setStatus = (message, mode = 'idle') => {
      if (!statusEl) return;
      statusEl.textContent = message;
      statusEl.dataset.status = mode;
    };

    const setBusy = (busy) => {
      container.setAttribute('aria-busy', busy ? 'true' : 'false');
    };

    const describeCacheAge = () => {
      if (typeof state.fetchedAt !== 'number') return '';
      const diff = Math.max(Date.now() - state.fetchedAt, 0);
      if (diff < 45000) return ' (<1 min old)';
      const minutes = Math.round(diff / 60000);
      return ` (~${minutes} min old)`;
    };

    const augmentStatusMessage = (
      message,
      options = { includeCacheAge: true }
    ) => {
      const parts = [message];

      if (
        options.includeCacheAge &&
        isCacheOrigin(state.origin) &&
        typeof state.fetchedAt === 'number'
      ) {
        parts.push(describeCacheAge());
      }

      return parts.join('');
    };

    const updateMeta = () => {
      if (!metaRoot) return;

      if (!state.rows.length) {
        metaRoot.hidden = true;
        return;
      }

      metaRoot.hidden = false;

      if (summaryPoolEl) {
        summaryPoolEl.textContent =
          state.previewPool > 0 ? formatNumber(state.previewPool) : '—';
      }

      if (metaOriginEl) {
        let originLabel = 'Network';
        if (state.origin === 'cache') originLabel = 'Cache (fresh)';
        else if (state.origin === 'cache-stale') originLabel = 'Cache (stale)';
        metaOriginEl.textContent = originLabel;
      }

      if (typeof state.fetchedAt === 'number') {
        const updatedLabel =
          formatTimestampForDisplay(state.fetchedAt / 1000) ?? '—';
        if (metaRefreshedEl) metaRefreshedEl.textContent = updatedLabel;
        const relative = formatRelativeTimeFromNow(state.fetchedAt / 1000);
        if (metaRelativeEl) {
          metaRelativeEl.textContent = relative ? ` (${relative})` : '';
        }
      } else {
        if (metaRefreshedEl) metaRefreshedEl.textContent = '—';
        if (metaRelativeEl) metaRelativeEl.textContent = '';
      }

      const oldestEl = qs('[data-preview-oldest]', container);
      const newestEl = qs('[data-preview-newest]', container);
      const oldestRelEl = qs(
        '[data-preview-oldest-relative]',
        container
      );
      const newestRelEl = qs(
        '[data-preview-newest-relative]',
        container
      );

      if (state.stats?.earliestFirstSeen && state.stats?.newestFirstSeen) {
        const earliest = state.stats.earliestFirstSeen;
        const newest = state.stats.newestFirstSeen;

        if (oldestEl) oldestEl.textContent = earliest.date ?? '—';
        if (newestEl) newestEl.textContent = newest.date ?? '—';
        if (oldestRelEl)
          oldestRelEl.textContent = earliest.relative ?? '—';
        if (newestRelEl)
          newestRelEl.textContent = newest.relative ?? '—';
      }
    };

    const updateSummary = (visibleRows) => {
      if (!summaryRoot) return;

      const totalRows = state.rows.length;
      const datasetSources = state.stats?.activeSources;
      const previewPool = state.previewPool ?? totalRows;
      const showSummary = totalRows > 0;

      summaryRoot.hidden = !showSummary;
      if (!showSummary) return;

      const visibleCount = visibleRows.length;
      const highCount = visibleRows.filter(
        (row) => confidenceRankForRow(row) >= 3
      ).length;

      if (summaryVisibleEl)
        summaryVisibleEl.textContent = formatNumber(visibleCount);
      if (summaryTotalEl)
        summaryTotalEl.textContent = formatNumber(totalRows);
      if (summaryHighEl)
        summaryHighEl.textContent = formatNumber(highCount);

      if (summaryHighPercentEl) {
        const percent =
          totalRows > 0 ? ((highCount / totalRows) * 100).toFixed(1) : '0.0';
        summaryHighPercentEl.textContent = `${percent}%`;
      }

      if (summaryPoolEl) {
        const poolText =
          previewPool && !Number.isNaN(previewPool)
            ? formatNumber(previewPool)
            : datasetSources != null
            ? formatNumber(datasetSources)
            : '—';
        summaryPoolEl.textContent = poolText;
      }

      const tagCounts = new Map();
      visibleRows.forEach((row) => {
        if (!row.tags || !row.tags.length) return;
        row.tags.forEach((tag, index) => {
          const key = row.tagsLower?.[index] || tag.toLowerCase();
          if (!tagCounts.has(key)) {
            tagCounts.set(key, { label: tag, count: 0 });
          }
          tagCounts.get(key).count += 1;
        });
      });

      let topTagEntry = null;
      tagCounts.forEach((entry) => {
        if (
          !topTagEntry ||
          entry.count > topTagEntry.count ||
          (entry.count === topTagEntry.count &&
            entry.label.localeCompare(topTagEntry.label) < 0)
        ) {
          topTagEntry = entry;
        }
      });

      if (summaryTopTagEl) {
        summaryTopTagEl.textContent = topTagEntry
          ? topTagEntry.label
          : 'No tags across highlighted sources';
      }

      if (summaryTopTagCountEl) {
        summaryTopTagCountEl.textContent = topTagEntry
          ? `${formatNumber(topTagEntry.count)} of ${formatNumber(
              visibleCount
            )}`
          : '—';
      }
    };

    const createPreviewRow = (row) => {
      const tr = document.createElement('tr');

      const indicatorCell = document.createElement('td');
      indicatorCell.dataset.title = 'Indicator';

      const indicatorWrapper = document.createElement('div');
      indicatorWrapper.className = 'preview-indicator';

      const indicatorMain = document.createElement('div');
      indicatorMain.className = 'preview-indicator-main';

      const indicatorCode = document.createElement('code');
      indicatorCode.textContent = row.indicator ?? '—';

      indicatorMain.appendChild(indicatorCode);

      if (row.tags && row.tags.length) {
        const tagsWrapper = document.createElement('div');
        tagsWrapper.className = 'preview-indicator-tags';
        row.tags.slice(0, 4).forEach((tag) => {
          const span = document.createElement('span');
          span.textContent = tag;
          tagsWrapper.appendChild(span);
        });
        indicatorMain.appendChild(tagsWrapper);
      }

      indicatorWrapper.appendChild(indicatorMain);

      const indicatorCopy = document.createElement('div');
      indicatorCopy.className = 'preview-indicator-copy';

      const copyButton = document.createElement('button');
      copyButton.type = 'button';
      copyButton.className = 'button-link';
      copyButton.textContent = 'Copy';

      const copyToClipboard = async (text) => {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
      };

      const setButtonState = (stateValue) => {
        if (stateValue === 'copied') {
          copyButton.textContent = 'Copied';
        } else if (stateValue === 'error') {
          copyButton.textContent = 'Error';
        } else if (stateValue === 'working') {
          copyButton.textContent = 'Copying…';
        } else {
          copyButton.textContent = 'Copy';
        }
      };

      copyButton.addEventListener('click', async () => {
        if (!row.indicator) return;
        copyButton.disabled = true;
        setButtonState('working');
        try {
          const success = await copyToClipboard(row.indicator);
          setButtonState(success ? 'copied' : 'error');
        } catch (error) {
          console.error('Failed to copy indicator to clipboard', error);
          setButtonState('error');
        }
        setTimeout(() => {
          setButtonState('idle');
          copyButton.disabled = false;
        }, 1600);
      });

      indicatorWrapper.appendChild(copyButton);
      indicatorCell.appendChild(indicatorWrapper);
      tr.appendChild(indicatorCell);

      const makeCell = (title, value, className) => {
        const td = document.createElement('td');
        td.dataset.title = title;
        if (className) td.classList.add(className);
        td.textContent = value ?? '—';
        return td;
      };

      tr.appendChild(makeCell('Type', row.type));
      tr.appendChild(makeCell('Source', row.source));
      tr.appendChild(makeCell('First seen', row.firstSeen));

      const confidenceClass = confidenceClassFor(row.confidence);
      const confidenceLabel = row.confidence || '—';
      tr.appendChild(
        makeCell('Confidence', confidenceLabel, confidenceClass)
      );

      return tr;
    };

    const filterRows = () => {
      const filter = state.filter;
      const tagFilter = state.tagFilter;
      const searchTerm = state.search.toLowerCase().trim();

      return state.rows.filter((row) => {
        if (filter !== 'all' && row.type.toLowerCase() !== filter) {
          return false;
        }

        if (tagFilter !== 'all') {
          if (!row.tagsLower || !row.tagsLower.includes(tagFilter)) {
            return false;
          }
        }

        if (searchTerm) {
          const haystack = [
            row.indicator,
            row.type,
            row.source,
            ...(row.tags || []),
          ]
            .join(' ')
            .toLowerCase();

          if (!haystack.includes(searchTerm)) {
            return false;
          }
        }

        return true;
      });
    };

    const renderRows = (rows) => {
      if (!tbody || !table) return;

      tbody.innerHTML = '';

      if (!rows.length) {
        table.hidden = true;
        return;
      }

      const fragment = document.createDocumentFragment();
      rows.forEach((row) => {
        fragment.appendChild(createPreviewRow(row));
      });
      tbody.appendChild(fragment);
      table.hidden = false;
    };

    const applyFilter = () => {
      const filtered = filterRows();

      if (!filtered.length) {
        renderRows([]);
        if (summaryRoot) {
          summaryRoot.hidden = true;
        }

        const searchTerm = state.search.toLowerCase().trim();
        const summaryParts = [];

        if (state.filter !== 'all')
          summaryParts.push(`type: ${state.filter}`);
        if (state.tagFilter !== 'all')
          summaryParts.push(`tag: ${state.tagFilter}`);
        if (searchTerm)
          summaryParts.push(`search: “${state.search.trim()}”`);

        const qualifier = summaryParts.length
          ? ` for ${summaryParts.join(', ')}`
          : '';

        setStatus(
          augmentStatusMessage(
            `No source highlights match the current filters${qualifier}. Adjust filters or refresh the feed.`
          ),
          'empty'
        );
        updateSummary([]);
        updateMeta();
        return;
      }

      const limited = filtered.slice(0, state.limit);
      renderRows(limited);
      updateSummary(limited);

      const searchTerm = state.search.toLowerCase().trim();
      const summaryParts = [];

      if (state.filter !== 'all')
        summaryParts.push(`type: ${state.filter}`);
      if (state.tagFilter !== 'all')
        summaryParts.push(
          `tag: ${buildSummaryLabel(tagFilterSelect, state.tagFilter)}`
        );
      if (searchTerm)
        summaryParts.push(`search: “${state.search.trim()}”`);

      const qualifier = summaryParts.length
        ? ` (${summaryParts.join(', ')})`
        : '';

      setStatus(
        augmentStatusMessage(
          `Showing ${limited.length} of ${filtered.length} matching source highlights${qualifier}.`
        ),
        'ready'
      );
    };

    const addOption = (select, value, label, count) => {
      if (!select) return;
      const option = document.createElement('option');
      option.value = value;
      option.textContent =
        count != null ? `${label} (${count})` : label;
      option.dataset.label = label;
      select.appendChild(option);
    };

    const populateFilterOptions = (rows) => {
      if (filterSelect) {
        const typeCounts = new Map();
        rows.forEach((row) => {
          const key = row.type.toLowerCase();
          typeCounts.set(key, (typeCounts.get(key) || 0) + 1);
        });

        filterSelect.innerHTML = '';
        addOption(filterSelect, 'all', 'All types');

        Array.from(typeCounts.entries())
          .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
          .forEach(([type, count]) => {
            addOption(filterSelect, type, type, count);
          });

        filterSelect.disabled = rows.length === 0;
      }

      if (tagFilterSelect) {
        const tagCounts = new Map();
        rows.forEach((row) => {
          if (!row.tagsLower || !row.tagsLower.length) return;
          row.tagsLower.forEach((key, index) => {
            const label = row.tags?.[index] || key;
            if (!tagCounts.has(key)) {
              tagCounts.set(key, { label, count: 0 });
            }
            tagCounts.get(key).count += 1;
          });
        });

        tagFilterSelect.innerHTML = '';
        addOption(tagFilterSelect, 'all', 'All tags');

        Array.from(tagCounts.entries())
          .sort(
            (a, b) => b[1].count - a[1].count ||
              a[1].label.localeCompare(b[1].label)
          )
          .forEach(([key, entry]) => {
            addOption(tagFilterSelect, key, entry.label, entry.count);
          });

        tagFilterSelect.disabled =
          rows.length === 0 || tagFilterSelect.options.length <= 1;
      }
    };

    const countDistinctSources = (rows) => {
      const set = new Set();
      rows.forEach((row) => {
        const source = normaliseLower(row.source);
        if (source) set.add(source);
      });
      return set.size;
    };

    const buildSummaryLabel = (select, value) => {
      if (!select) return value;
      const option = Array.from(select.options).find(
        (opt) => opt.value === value
      );
      return option?.dataset.label || value;
    };

    const loadPreview = async ({
      silent = false,
      forceRefresh = false,
    } = {}) => {
      if (!table || !tbody) return;

      state.loading = true;
      container.dataset.loading = 'true';

      setBusy(true);
      table.hidden = true;
      tbody.innerHTML = '';

      setStatus(
        silent ? 'Refreshing source highlights…' : 'Loading source highlights…',
        'loading'
      );
      toggleControls(true);

      try {
        const { dataset, previewRows } = await loadDataset({
          previewLimit: state.limit,
          forceRefresh,
        });

        state.rows = previewRows;
        state.origin = dataset.origin || 'network';
        state.fetchedAt =
          typeof dataset.fetchedAt === 'number'
            ? dataset.fetchedAt
            : null;
        state.stats = dataset.stats || state.stats;

        const sourcePool = countDistinctSources(dataset.previewEntries || []);
        const fallbackPool = countDistinctSources(previewRows);
        state.previewPool = sourcePool > 0 ? sourcePool : fallbackPool;

        updateMeta();
        populateFilterOptions(previewRows);
        applyFilter();

        if (forceRefresh || !isCacheOrigin(dataset.origin)) {
          applyStats(dataset.stats, dataset);
        }
      } catch (error) {
        console.error('Unable to load live preview data', error);
        state.rows = [];
        state.origin = 'network';
        state.fetchedAt = null;
        state.stats = null;
        state.previewPool = 0;
        if (tbody) tbody.innerHTML = '';
        setStatus(
          'Unable to load the source preview. Try again shortly or download the full feed below.',
          'error'
        );
        updateSummary([]);
        if (metaRoot) metaRoot.hidden = true;
      } finally {
        // re-enable with specific logic
        if (filterSelect) filterSelect.disabled = state.rows.length === 0;

        if (tagFilterSelect) {
          tagFilterSelect.disabled =
            state.rows.length === 0 ||
            !tagFilterSelect.options ||
            tagFilterSelect.options.length <= 1;
        }

        if (searchInput) {
          searchInput.disabled = state.rows.length === 0;
          if (!searchInput.disabled) {
            searchInput.value = state.search;
          }
        }

        if (limitSelect) limitSelect.disabled = false;
        if (refreshButton) refreshButton.disabled = false;

        state.loading = false;
        delete container.dataset.loading;

        setBusy(false);
      }
    };

    const toggleControls = (disabled) => {
      if (filterSelect) filterSelect.disabled = disabled;
      if (tagFilterSelect) tagFilterSelect.disabled = disabled;
      if (searchInput) searchInput.disabled = disabled;
      if (limitSelect) limitSelect.disabled = disabled;
      if (refreshButton) refreshButton.disabled = disabled;
    };

    let searchDebounce = null;

    if (filterSelect) {
      filterSelect.addEventListener('change', () => {
        state.filter = filterSelect.value;
        applyFilter();
      });
    }

    if (tagFilterSelect) {
      tagFilterSelect.addEventListener('change', () => {
        state.tagFilter = tagFilterSelect.value;
        applyFilter();
      });
    }

    if (limitSelect) {
      limitSelect.addEventListener('change', () => {
        const value = parseInt(limitSelect.value, 10);
        if (!Number.isNaN(value) && value > 0) {
          state.limit = value;
          applyFilter();
        }
      });
    }

    if (searchInput) {
      searchInput.addEventListener('input', (event) => {
        const value = event.target.value;
        if (searchDebounce) clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
          state.search = value;
          applyFilter();
        }, 220);
      });

      searchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          if (searchDebounce) clearTimeout(searchDebounce);
          state.search = event.target.value;
          applyFilter();
        } else if (event.key === 'Escape') {
          event.target.value = '';
          state.search = '';
          applyFilter();
        }
      });
    }

    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        loadPreview({ forceRefresh: true });
      });
    }

    subscribeToDataset((dataset) => {
      if (!dataset || !table || !tbody) return;
      if (isCacheOrigin(dataset.origin)) return;

      state.stats = dataset.stats || state.stats;
      applyStats(dataset.stats, dataset);
    });

    // Single-screen dashboard: load immediately
    loadPreview();
  };

  /* ==========================================================================
   *  BOOTSTRAP
   * ========================================================================= */

  initialiseStatusBanner();
  loadStats();
  initialisePreview();
})();
