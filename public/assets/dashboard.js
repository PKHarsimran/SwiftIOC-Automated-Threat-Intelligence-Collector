(function () {
  'use strict';

  /* ==========================================================================
   *  CONFIG & CONSTANTS
   * ========================================================================= */

  const IOC_ROOT = document.body?.dataset.iocRoot || '.';

  const DEFAULT_PREVIEW_LIMIT = 12;
  const PREVIEW_LOOKAHEAD_MULTIPLIER = 12;
  const PREVIEW_CACHE_LIMIT = Math.max(
    DEFAULT_PREVIEW_LIMIT * PREVIEW_LOOKAHEAD_MULTIPLIER,
    240
  );

  const INDICATORS_JSONL_URL = `${IOC_ROOT}/iocs/latest.jsonl`;
  const INDICATORS_JSON_FALLBACK_URL = `${IOC_ROOT}/iocs/latest.json`;
  const PREVIEW_STREAM_URL = INDICATORS_JSONL_URL;

  const DATASET_STORAGE_KEY = 'swiftioc-dashboard-cache-v1';
  const DATASET_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  const UNKNOWN_SOURCE_KEY = '__swiftioc-unknown-source__';

  /* ==========================================================================
   *  FORMATTERS
   * ========================================================================= */

  const numberFormatter = new Intl.NumberFormat('en-US');
  const formatNumber = (value) => numberFormatter.format(value ?? 0);

  const relativeTimeFormatter =
    typeof Intl !== 'undefined' &&
    typeof Intl.RelativeTimeFormat === 'function'
      ? new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
      : null;

  const relativeDivisions = [
    { amount: 60, unit: 'second' },
    { amount: 60, unit: 'minute' },
    { amount: 24, unit: 'hour' },
    { amount: 7, unit: 'day' },
    { amount: 4.34524, unit: 'week' },
    { amount: 12, unit: 'month' },
    { amount: Infinity, unit: 'year' },
  ];

  const dateTimeFormatter =
    typeof Intl !== 'undefined' &&
    typeof Intl.DateTimeFormat === 'function'
      ? new Intl.DateTimeFormat('en-US', {
          dateStyle: 'medium',
          timeStyle: 'short',
        })
      : null;

  const formatRelativeTimeFromNow = (timestamp) => {
    if (!relativeTimeFormatter || typeof timestamp !== 'number') return null;
    const now = Date.now();
    let delta = Math.round((timestamp - now) / 1000);

    for (const division of relativeDivisions) {
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

  /* ==========================================================================
   *  BASIC HELPERS
   * ========================================================================= */

  const qs = (selector, root = document) => root.querySelector(selector);
  const qsa = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

  const normaliseString = (value) => (value ?? '').toString().trim();
  const normaliseLower = (value) => normaliseString(value).toLowerCase();

  const coalesceString = (...values) => {
    for (const value of values) {
      const normalised = normaliseString(value);
      if (normalised) return normalised;
    }
    return '';
  };

  const uniqueStrings = (values) => {
    const seen = new Set();
    const result = [];
    (values || []).forEach((value) => {
      const normalised = normaliseString(value);
      if (!normalised) return;
      const key = normaliseLower(normalised);
      if (seen.has(key)) return;
      seen.add(key);
      result.push(normalised);
    });
    return result;
  };

  const safeParseJson = (line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  };

  const parseTimestamp = (value) => {
    if (!value) return null;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    return {
      iso: date.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      time: date.getTime(),
    };
  };

  const isoToParts = (iso) => {
    if (!iso) return { date: null, time: null };
    const [datePart, timePart] = iso.split('T');
    const cleaned = (timePart || '').replace('Z', '');
    const hhmmss = cleaned ? `${cleaned.slice(0, 8)}Z` : null;
    return {
      date: datePart || null,
      time: hhmmss,
    };
  };

  /* ==========================================================================
   *  CONFIDENCE RANKING
   * ========================================================================= */

  const confidenceRankForValue = (confidence) => {
    const value = normaliseLower(confidence);
    if (!value) return 0;

    if (value.includes('very high') || value.includes('critical')) return 4;
    if (value.includes('high')) return 3;
    if (value.includes('medium') || value.includes('moderate')) return 2;
    if (value.includes('low')) return 1;

    const numeric = Number.parseFloat(value);
    if (Number.isFinite(numeric)) {
      if (numeric >= 90) return 4;
      if (numeric >= 80) return 3;
      if (numeric >= 50) return 2;
      if (numeric > 0) return 1;
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
   *  DATASET CACHE (sessionStorage)
   * ========================================================================= */

  const createDatasetStorage = () => {
    let storageChecked = false;
    let storage = null;

    const resolveStorage = () => {
      if (storageChecked) return storage;
      storageChecked = true;

      try {
        if (typeof window === 'undefined' || !window.sessionStorage) {
          storage = null;
          return storage;
        }
        const testKey = `${DATASET_STORAGE_KEY}__test`;
        window.sessionStorage.setItem(testKey, '1');
        window.sessionStorage.removeItem(testKey);
        storage = window.sessionStorage;
      } catch (error) {
        console.warn('Session storage unavailable for dataset caching', error);
        storage = null;
      }
      return storage;
    };

    const read = () => {
      const target = resolveStorage();
      if (!target) return null;

      try {
        const raw = target.getItem(DATASET_STORAGE_KEY);
        if (!raw) return null;

        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object') {
          target.removeItem(DATASET_STORAGE_KEY);
          return null;
        }

        if (
          typeof parsed.timestamp !== 'number' ||
          typeof parsed.dataset !== 'object' ||
          !parsed.dataset
        ) {
          target.removeItem(DATASET_STORAGE_KEY);
          return null;
        }

        const dataset = parsed.dataset;
        const age = Date.now() - parsed.timestamp;
        const stale = age > DATASET_CACHE_TTL;

        dataset.fetchedAt =
          typeof dataset.fetchedAt === 'number'
            ? dataset.fetchedAt
            : parsed.timestamp;
        dataset.origin = stale ? 'cache-stale' : 'cache';

        return dataset;
      } catch (error) {
        console.warn('Failed to read cached dataset', error);
        try {
          target.removeItem(DATASET_STORAGE_KEY);
        } catch (cleanupError) {
          console.warn('Failed to clear corrupt dataset cache', cleanupError);
        }
        return null;
      }
    };

    const write = (dataset) => {
      const target = resolveStorage();
      if (!target || !dataset) return;

      try {
        const datasetToStore = {
          ...dataset,
          origin: 'network',
          fetchedAt:
            typeof dataset.fetchedAt === 'number'
              ? dataset.fetchedAt
              : Date.now(),
        };

        const payload = JSON.stringify({
          timestamp: Date.now(),
          dataset: datasetToStore,
        });

        target.setItem(DATASET_STORAGE_KEY, payload);
      } catch (error) {
        console.warn('Failed to persist dataset cache', error);
      }
    };

    const clear = () => {
      const target = resolveStorage();
      if (!target) return;
      try {
        target.removeItem(DATASET_STORAGE_KEY);
      } catch (error) {
        console.warn('Failed to clear dataset cache', error);
      }
    };

    return { read, write, clear };
  };

  const datasetStorage = createDatasetStorage();

  /* ==========================================================================
   *  STATS ACCUMULATION
   * ========================================================================= */

  const createStatsAccumulator = () => {
    const bySource = new Map();
    const byType = new Map();
    const tags = new Map();
    const indicatorCounts = new Map();
    const indicatorSources = new Map();

    let earliestFirstSeen = null;
    let newestFirstSeen = null;
    let latestObservation = null;
    let total = 0;

    const registerTags = (row) => {
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

    return {
      ingest(row) {
        if (!row || typeof row !== 'object') return;

        total += 1;

        const source = normaliseString(row.source);
        const type = normaliseString(row.type);
        const indicator = normaliseString(row.indicator);

        if (source) {
          bySource.set(source, (bySource.get(source) || 0) + 1);
        }
        if (type) {
          byType.set(type, (byType.get(type) || 0) + 1);
        }

        if (indicator) {
          indicatorCounts.set(
            indicator,
            (indicatorCounts.get(indicator) || 0) + 1
          );
          if (source) {
            if (!indicatorSources.has(indicator)) {
              indicatorSources.set(indicator, new Set());
            }
            indicatorSources.get(indicator).add(source);
          }
        }

        const firstSeen = parseTimestamp(row.first_seen ?? row.firstSeen);
        const lastSeen = parseTimestamp(row.last_seen ?? row.lastSeen);

        if (firstSeen) {
          if (!earliestFirstSeen || firstSeen.time < earliestFirstSeen.time) {
            earliestFirstSeen = firstSeen;
          }
          if (!newestFirstSeen || firstSeen.time > newestFirstSeen.time) {
            newestFirstSeen = firstSeen;
          }
          if (!latestObservation || firstSeen.time > latestObservation.time) {
            latestObservation = firstSeen;
          }
        }

        if (lastSeen) {
          if (!latestObservation || lastSeen.time > latestObservation.time) {
            latestObservation = lastSeen;
          }
        }

        registerTags(row);
      },

      finalize() {
        const sortedSources = Array.from(bySource.entries()).sort(
          (a, b) => b[1] - a[1]
        );
        const sortedTypes = Array.from(byType.entries()).sort(
          (a, b) => b[1] - a[1]
        );
        const sortedTags = Array.from(tags.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10);

        const earliestParts = earliestFirstSeen
          ? isoToParts(earliestFirstSeen.iso)
          : { date: null, time: null };

        const newestParts = newestFirstSeen
          ? isoToParts(newestFirstSeen.iso)
          : { date: null, time: null };

        let collectionWindow = null;
        if (earliestParts.date && newestParts.date) {
          collectionWindow = `${earliestParts.date} → ${newestParts.date}`;
        } else if (earliestParts.date) {
          collectionWindow = earliestParts.date;
        } else if (newestParts.date) {
          collectionWindow = newestParts.date;
        }

        const uniqueIndicators = indicatorCounts.size;
        const duplicatesRemoved = Math.max(total - uniqueIndicators, 0);
        const multiSourceOverlaps = Array.from(
          indicatorSources.values()
        ).filter((sources) => sources.size > 1).length;

        return {
          total,
          duplicatesRemoved,
          activeSources: bySource.size,
          indicatorTypes: byType.size,
          multiSourceOverlaps,
          bySource: sortedSources,
          byType: sortedTypes,
          topTags: sortedTags,
          earliestFirstSeen: earliestParts,
          newestFirstSeen: newestParts,
          generatedAt: latestObservation?.iso ?? null,
          collectionWindow,
        };
      },
    };
  };

  const computeStatsFromIterable = (iterable) => {
    const acc = createStatsAccumulator();
    for (const row of iterable || []) {
      acc.ingest(row);
    }
    return acc.finalize();
  };

  /* ==========================================================================
   *  TABLE + STAT DOM HELPERS
   * ========================================================================= */

  const getStatTargets = (name) =>
    qsa(`[data-stat="${name}"]`, document);

  const setStatText = (name, value) => {
    getStatTargets(name).forEach((el) => {
      el.textContent = value ?? '—';
    });
  };

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
   *  PREVIEW ROWS + SELECTION
   * ========================================================================= */

  const compareRowStrength = (a, b) => {
    if (!a && !b) return 0;
    if (!a) return 1;
    if (!b) return -1;

    const rankDiff = confidenceRankForRow(b) - confidenceRankForRow(a);
    if (rankDiff !== 0) return rankDiff;

    const timeDiff = (b.firstSeenTime ?? 0) - (a.firstSeenTime ?? 0);
    if (timeDiff !== 0) return timeDiff;

    const sourceDiff = normaliseString(a.source).localeCompare(
      normaliseString(b.source)
    );
    if (sourceDiff !== 0) return sourceDiff;

    return normaliseString(a.indicator).localeCompare(
      normaliseString(b.indicator)
    );
  };

  const selectBestPerSource = (rows) => {
    if (!Array.isArray(rows) || !rows.length) return [];

    const best = new Map();
    rows.forEach((row) => {
      if (!row) return;
      const key = row.sourceLower || UNKNOWN_SOURCE_KEY;
      const current = best.get(key);
      if (!current || compareRowStrength(row, current) < 0) {
        best.set(key, row);
      }
    });

    return Array.from(best.values()).sort(compareRowStrength);
  };

  const countDistinctSources = (rows) => {
    if (!Array.isArray(rows) || !rows.length) return 0;
    const seen = new Set();
    rows.forEach((row) => {
      if (!row) return;
      const key = row.sourceLower || UNKNOWN_SOURCE_KEY;
      seen.add(key);
    });
    return seen.size;
  };

  const selectDiverseRows = (rows, limit) => {
    const candidates = selectBestPerSource(rows || []);
    if (!candidates.length) return [];

    const max = Math.max(Number(limit) || DEFAULT_PREVIEW_LIMIT, 1);
    const remaining = candidates.slice();
    const selected = [];
    const usedTags = new Set();

    while (remaining.length && selected.length < max) {
      let bestIndex = -1;
      let bestRow = null;
      let bestNewTags = -1;

      remaining.forEach((row, index) => {
        if (!row) return;
        const newTags = row.tagsLower.filter(
          (tag) => !usedTags.has(tag)
        ).length;

        if (bestIndex === -1) {
          bestIndex = index;
          bestRow = row;
          bestNewTags = newTags;
          return;
        }

        if (newTags > bestNewTags) {
          bestIndex = index;
          bestRow = row;
          bestNewTags = newTags;
          return;
        }

        if (
          newTags === bestNewTags &&
          compareRowStrength(row, bestRow) < 0
        ) {
          bestIndex = index;
          bestRow = row;
        }
      });

      if (bestIndex === -1) break;

      const [chosen] = remaining.splice(bestIndex, 1);
      if (!chosen) break;

      selected.push(chosen);
      chosen.tagsLower.forEach((tag) => usedTags.add(tag));
    }

    if (selected.length < max && remaining.length) {
      remaining
        .sort(compareRowStrength)
        .slice(0, max - selected.length)
        .forEach((row) => {
          if (!row) return;
          selected.push(row);
        });
    }

    return selected.sort(compareRowStrength);
  };

  const preparePreviewRow = (row) => {
    if (!row || typeof row !== 'object') return null;

    const indicator = coalesceString(
      row.indicator,
      row.observable,
      row.observable_value,
      row.value,
      row.domain,
      row.url,
      row.hash,
      row.address
    );
    if (!indicator) return null;

    const typeRaw = coalesceString(
      row.type,
      row.indicator_type,
      row.observable_type,
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
      ...extractTags(row.sectors),
      ...extractTags(row.industries),
    ];
    const tags = uniqueStrings(tagValues).slice(0, 8);

    const firstSeenRaw = coalesceString(
      row.first_seen,
      row.firstSeen,
      row.first_observed,
      row.firstObservation,
      row.first_observed_at,
      row.created,
      row.created_at,
      row.observed,
      row.observed_at,
      row.timestamp,
      row.date_seen,
      row.last_seen,
      row.lastSeen,
      row.seen
    );
    const firstSeenParsed = parseTimestamp(firstSeenRaw);
    const firstSeenDisplay = formatTimestampForDisplay(
      firstSeenParsed?.iso ?? firstSeenRaw
    );

    return {
      indicator,
      indicatorLower: indicator.toLowerCase(),
      type: typeRaw || '—',
      typeKey: typeRaw ? typeRaw.toLowerCase() : 'unknown',
      source: sourceRaw || '—',
      sourceLower: sourceRaw ? sourceRaw.toLowerCase() : '',
      firstSeen: firstSeenDisplay,
      firstSeenTime: firstSeenParsed?.time ?? null,
      confidence: confidenceRaw || '—',
      confidenceLower: confidenceRaw ? confidenceRaw.toLowerCase() : '',
      confidenceRank: confidenceRankForValue(confidenceRaw),
      tags,
      tagsLower: tags.map((tag) => tag.toLowerCase()),
      searchBlob: [
        indicator,
        typeRaw,
        sourceRaw,
        confidenceRaw,
        firstSeenRaw,
        ...tags,
      ]
        .filter(Boolean)
        .map((value) => value.toLowerCase())
        .join(' '),
    };
  };

  /* ==========================================================================
   *  STREAM JSONL
   * ========================================================================= */

  const streamJsonLines = async (url, { limit = Infinity, onRow } = {}) => {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`Unable to fetch ${url} (${response.status})`);
    }

    let processed = 0;
    const handleRow = typeof onRow === 'function' ? onRow : () => {};

    const processLine = (line) => {
      const trimmed = line.trim();
      if (!trimmed) return false;
      const parsed = safeParseJson(trimmed);
      if (!parsed) return false;
      const shouldStop = handleRow(parsed) === true;
      processed += 1;
      if (shouldStop) return true;
      return processed >= limit;
    };

    // Fallback for environments without streaming
    if (!response.body || !response.body.getReader) {
      const text = await response.text();
      const lines = text.split(/\r?\n/);
      for (const line of lines) {
        if (processLine(line)) break;
      }
      return processed;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split(/\r?\n/);
        buffer = parts.pop() ?? '';

        for (const part of parts) {
          if (processLine(part)) {
            await reader.cancel().catch(() => {});
            return processed;
          }
        }
      }

      const remainder = buffer.trim();
      if (remainder) processLine(remainder);
    } finally {
      if (reader.releaseLock) {
        reader.releaseLock();
      }
    }

    return processed;
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

  const wrapDatasetPromise = (promise) => {
    const wrapped = promise
      .then((dataset) => {
        notifyDatasetListeners(dataset);
        return dataset;
      })
      .catch((error) => {
        if (datasetCache.promise === wrapped) {
          datasetCache.promise = null;
        }
        throw error;
      });

    datasetCache.promise = wrapped;
    return wrapped;
  };

  const fetchDatasetFromJson = async () => {
    const response = await fetch(INDICATORS_JSON_FALLBACK_URL, {
      cache: 'no-store',
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch preview fallback (${response.status})`);
    }

    const indicators = await response.json();
    const iterable = Array.isArray(indicators) ? indicators : [];
    const stats = computeStatsFromIterable(iterable);

    const previewEntries = [];
    const seen = new Set();

    for (const row of iterable) {
      if (previewEntries.length >= PREVIEW_CACHE_LIMIT) break;
      const entry = preparePreviewRow(row);
      if (!entry) continue;
      if (seen.has(entry.indicatorLower)) continue;
      seen.add(entry.indicatorLower);
      previewEntries.push(entry);
    }

    return { stats, previewEntries, source: 'json' };
  };

  const fetchDatasetFromStream = async () => {
    const accumulator = createStatsAccumulator();
    const previewEntries = [];
    const seen = new Set();

    await streamJsonLines(PREVIEW_STREAM_URL, {
      onRow: (row) => {
        accumulator.ingest(row);

        if (previewEntries.length < PREVIEW_CACHE_LIMIT) {
          const entry = preparePreviewRow(row);
          if (entry && !seen.has(entry.indicatorLower)) {
            seen.add(entry.indicatorLower);
            previewEntries.push(entry);
          }
        }

        return false;
      },
    });

    const stats = accumulator.finalize();

    if (!previewEntries.length) {
      try {
        const fallback = await fetchDatasetFromJson();
        return {
          stats,
          previewEntries: fallback.previewEntries,
          source: fallback.source,
        };
      } catch (fallbackError) {
        console.warn(
          'Failed to augment preview entries via JSON fallback',
          fallbackError
        );
      }
    }

    return { stats, previewEntries, source: 'jsonl' };
  };

  const fetchFreshDataset = async () => {
    const fetchedAt = Date.now();
    try {
      const dataset = await fetchDatasetFromStream();
      const enriched = { ...dataset, origin: 'network', fetchedAt };
      datasetStorage.write(enriched);
      return enriched;
    } catch (streamError) {
      console.warn('Streaming dataset failed, falling back to JSON', streamError);
      const dataset = await fetchDatasetFromJson();
      const enriched = { ...dataset, origin: 'network', fetchedAt };
      datasetStorage.write(enriched);
      return enriched;
    }
  };

  const resolveDataset = async ({ forceRefresh = false } = {}) => {
    if (forceRefresh) {
      datasetStorage.clear();
      datasetCache.promise = null;
      datasetCache.refreshing = null;
    }

    if (!datasetCache.promise) {
      if (!forceRefresh) {
        const cached = datasetStorage.read();
        if (cached) {
          const resolved = wrapDatasetPromise(Promise.resolve(cached));

          // Background refresh
          if (!datasetCache.refreshing) {
            const refresh = fetchFreshDataset()
              .then((dataset) => {
                if (dataset) wrapDatasetPromise(Promise.resolve(dataset));
                return dataset;
              })
              .catch((error) => {
                console.warn('Background dataset refresh failed', error);
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
        }
      }
      return wrapDatasetPromise(fetchFreshDataset());
    }

    if (forceRefresh) {
      return wrapDatasetPromise(fetchFreshDataset());
    }

    return datasetCache.promise;
  };

  const loadDataset = async ({
    previewLimit = DEFAULT_PREVIEW_LIMIT,
    forceRefresh = false,
  } = {}) => {
    const dataset = await resolveDataset({ forceRefresh });

    const desired = Math.max(Number(previewLimit) || DEFAULT_PREVIEW_LIMIT, 1);
    const previewSource = Array.isArray(dataset.previewEntries)
      ? dataset.previewEntries
      : [];
    const previewRows = selectDiverseRows(previewSource, desired);

    return { dataset, previewRows };
  };

  /* ==========================================================================
   *  STATUS BANNER
   * ========================================================================= */

  const initialiseStatusBanner = () => {
    const root = qs('[data-site-status-root]');
    if (!root) return;

    const statusLabel = qs('[data-site-status-label]', root);
    const originEl = qs('[data-site-origin]', root);
    const windowEl = qs('[data-site-window]', root);
    const generatedEl = qs('[data-site-generated]', root);
    const updatedEl = qs('[data-site-updated]', root);
    const refreshButton = qs('[data-site-refresh]', root);

    const setState = (dataset) => {
      const stats = dataset?.stats || {};
      const origin = dataset?.origin || 'network';
      const fetchedAt =
        typeof dataset?.fetchedAt === 'number' ? dataset.fetchedAt : null;
      const total = stats?.total ?? 0;

      root.dataset.state = origin;

      if (statusLabel) {
        statusLabel.textContent =
          total > 0
            ? 'Dashboard is ready with fresh indicators'
            : 'Preparing dashboard…';
      }

      if (originEl) {
        let originLabel = 'Live dataset';
        if (origin === 'cache') originLabel = 'Cached snapshot';
        else if (origin === 'cache-stale') originLabel = 'Stale snapshot';
        originEl.textContent = originLabel;
      }

      if (windowEl) {
        windowEl.textContent = stats.collectionWindow ?? '—';
      }

      if (generatedEl) {
        generatedEl.textContent = formatTimestampForDisplay(stats.generatedAt);
      }

      if (updatedEl) {
        if (typeof fetchedAt === 'number') {
          const absolute = formatAbsoluteTimestamp(fetchedAt);
          const relative = formatRelativeTimeFromNow(fetchedAt);
          updatedEl.textContent = absolute
            ? `${absolute}${relative ? ` (${relative})` : ''}`
            : '—';
        } else {
          updatedEl.textContent = '—';
        }
      }
    };

    const handleError = () => {
      root.dataset.state = 'error';
      if (statusLabel) {
        statusLabel.textContent =
          'Unable to load the latest dataset right now';
      }
      if (originEl) originEl.textContent = 'Unavailable';
      if (windowEl) windowEl.textContent = '—';
      if (generatedEl) generatedEl.textContent = '—';
      if (updatedEl) updatedEl.textContent = '—';
    };

    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        root.dataset.state = 'refreshing';
        if (statusLabel) statusLabel.textContent = 'Refreshing data…';

        loadDataset({ forceRefresh: true })
          .then(({ dataset }) => setState(dataset))
          .catch(handleError);
      });
    }

    loadDataset()
      .then(({ dataset }) => setState(dataset))
      .catch(handleError);

    subscribeToDataset((dataset) => {
      if (!dataset) return;
      setState(dataset);
    });
  };

  /* ==========================================================================
   *  STATS PANEL
   * ========================================================================= */

  const applyStats = (stats) => {
    if (!stats) return;

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
    setStatText(
      'generated-at',
      formatTimestampForDisplay(stats.generatedAt)
    );

    setStatText(
      'earliest-first-seen-date',
      stats.earliestFirstSeen.date ?? '—'
    );
    setStatText(
      'earliest-first-seen-time',
      stats.earliestFirstSeen.time ?? '—'
    );
    setStatText(
      'newest-first-seen-date',
      stats.newestFirstSeen.date ?? '—'
    );
    setStatText(
      'newest-first-seen-time',
      stats.newestFirstSeen.time ?? '—'
    );
    setStatText(
      'multi-source-overlaps',
      formatNumber(stats.multiSourceOverlaps)
    );

    const sourceRows = stats.bySource.map(([source, count]) => [
      { title: 'Source', value: source },
      { title: 'Indicators', value: formatNumber(count), numeric: true },
    ]);
    populateTable('sources', sourceRows, 'No source data available.');

    const typeRows = stats.byType.map(([type, count]) => [
      { title: 'Type', value: type },
      { title: 'Indicators', value: formatNumber(count), numeric: true },
    ]);
    populateTable('types', typeRows, 'No indicator type data available.');

    const tagRows = stats.topTags.map(([tag, count]) => [
      { title: 'Tag', value: tag },
      { title: 'Indicators', value: formatNumber(count), numeric: true },
    ]);
    populateTable('tags', tagRows, 'No tags available yet.');
  };

  const loadStats = async (forceRefresh = false) => {
    try {
      const { dataset } = await loadDataset({ forceRefresh });
      applyStats(dataset.stats);
    } catch (error) {
      console.error('Failed to load indicator statistics', error);
      setStatText('total-indicators', '—');
      setStatText('duplicates-removed', '—');
      setStatText('active-sources', '—');
      setStatText('indicator-types', '—');
      setStatText('feeds-online', 'Unavailable');
      setStatText('collection-window', '—');
      setStatText('generated-at', 'Unavailable');
      setStatText('earliest-first-seen-date', '—');
      setStatText('earliest-first-seen-time', '—');
      setStatText('newest-first-seen-date', '—');
      setStatText('newest-first-seen-time', '—');
      setStatText('multi-source-overlaps', '—');
      populateTable('sources', [], 'Source data unavailable.');
      populateTable('types', [], 'Indicator type data unavailable.');
      populateTable('tags', [], 'Tag data unavailable.');
    }
  };

  subscribeToDataset((dataset) => {
    if (!dataset || isCacheOrigin(dataset.origin)) return;
    applyStats(dataset.stats);
  });

  /* ==========================================================================
   *  PREVIEW PANEL
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
    const summaryNewestEl = qs('[data-preview-newest]', container);
    const summaryNewestRelativeEl = qs(
      '[data-preview-newest-relative]',
      container
    );

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
      statusEl.dataset.state = mode;
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

    const augmentStatusMessage = (message) => {
      if (state.origin === 'cache-stale') {
        return `${message} Cached snapshot${describeCacheAge()} is older than the refresh window—fetching fresh data…`;
      }
      if (state.origin === 'cache') {
        return `${message} Cached snapshot${describeCacheAge()}—refreshing in the background…`;
      }
      return message;
    };

    const updateMeta = () => {
      if (!metaRoot) return;
      const showMeta =
        state.rows.length > 0 || typeof state.fetchedAt === 'number';
      metaRoot.hidden = !showMeta;

      if (metaOriginEl) {
        let originLabel = 'Live data';
        if (state.origin === 'cache') originLabel = 'Cached snapshot';
        else if (state.origin === 'cache-stale') originLabel = 'Stale snapshot';
        metaOriginEl.textContent = originLabel;
        metaOriginEl.dataset.state = state.origin;
      }

      if (metaRefreshedEl) {
        if (typeof state.fetchedAt === 'number') {
          const absolute = formatAbsoluteTimestamp(state.fetchedAt);
          metaRefreshedEl.textContent = absolute || '—';
          const iso = new Date(state.fetchedAt).toISOString();
          metaRefreshedEl.setAttribute('data-datetime', iso);
        } else {
          metaRefreshedEl.textContent = '—';
          metaRefreshedEl.removeAttribute('data-datetime');
        }
      }

      if (metaRelativeEl) {
        if (typeof state.fetchedAt === 'number') {
          const relative = formatRelativeTimeFromNow(state.fetchedAt);
          metaRelativeEl.textContent = relative ? `(${relative})` : '';
        } else {
          metaRelativeEl.textContent = '';
        }
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

      const visibleCount = Array.isArray(visibleRows)
        ? visibleRows.length
        : 0;

      if (summaryVisibleEl) {
        summaryVisibleEl.textContent = formatNumber(visibleCount);
      }
      if (summaryTotalEl) {
        const totalValue =
          datasetSources != null ? datasetSources : previewPool;
        summaryTotalEl.textContent = formatNumber(totalValue);
      }

      const highCount = (visibleRows || []).reduce((acc, row) => {
        return confidenceRankForRow(row) >= 3 ? acc + 1 : acc;
      }, 0);

      if (summaryHighEl) {
        summaryHighEl.textContent = formatNumber(highCount);
      }
      if (summaryHighPercentEl) {
        const percent = visibleCount
          ? Math.round((highCount / visibleCount) * 100)
          : 0;
        summaryHighPercentEl.textContent = `${percent}%`;
      }

      const tagCounts = new Map();
      (visibleRows || []).forEach((row) => {
        if (!row?.tags?.length) return;
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
          ? `${formatNumber(
              topTagEntry.count
            )} source${topTagEntry.count === 1 ? '' : 's'}`
          : '—';
      }

      let newestRow = null;
      (visibleRows || []).forEach((row) => {
        if (!row) return;
        if (!newestRow) {
          newestRow = row;
          return;
        }
        const currentTime = row.firstSeenTime ?? -Infinity;
        const newestTime = newestRow.firstSeenTime ?? -Infinity;
        if (currentTime > newestTime) {
          newestRow = row;
        }
      });

      if (summaryNewestEl) {
        summaryNewestEl.textContent = newestRow?.firstSeen ?? '—';
      }
      if (summaryNewestRelativeEl) {
        summaryNewestRelativeEl.textContent = newestRow?.firstSeenTime
          ? formatRelativeTimeFromNow(newestRow.firstSeenTime) || ''
          : '';
      }
    };

    const copyToClipboard = async (text) => {
      if (!text) return false;

      try {
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(text);
          return true;
        }
      } catch (error) {
        console.warn('Clipboard API failed, falling back to execCommand', error);
      }

      let textarea;
      try {
        textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
      } catch (error) {
        if (textarea && textarea.parentNode) {
          textarea.parentNode.removeChild(textarea);
        }
        console.error('execCommand copy fallback failed', error);
        return false;
      }
    };

    const renderRows = (rows) => {
      if (!tbody) return;
      tbody.innerHTML = '';

      const fragment = document.createDocumentFragment();

      rows.forEach((row) => {
        const tr = document.createElement('tr');

        const indicatorCell = document.createElement('td');
        indicatorCell.dataset.title = 'Indicator';
        indicatorCell.classList.add('indicator-cell');

        const indicatorWrapper = document.createElement('div');
        indicatorWrapper.className = 'indicator-wrapper';

        const indicatorValue = document.createElement('code');
        indicatorValue.className = 'indicator-value';
        indicatorValue.textContent = row.indicator;
        indicatorWrapper.appendChild(indicatorValue);

        const copyButton = document.createElement('button');
        copyButton.type = 'button';
        copyButton.className = 'copy-indicator';
        copyButton.setAttribute(
          'aria-label',
          `Copy indicator ${row.indicator}`
        );

        const setButtonState = (buttonState) => {
          copyButton.dataset.state = buttonState;
          if (buttonState === 'copied') {
            copyButton.textContent = 'Copied!';
          } else if (buttonState === 'error') {
            copyButton.textContent = 'Copy failed';
          } else if (buttonState === 'working') {
            copyButton.textContent = 'Copying…';
          } else {
            copyButton.textContent = 'Copy';
          }
        };

        setButtonState('idle');

        copyButton.addEventListener('click', async () => {
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

        const confidenceCell = makeCell(
          'Confidence',
          row.confidence,
          'confidence-cell'
        );
        const confidenceClass = confidenceClassFor(row.confidence);
        if (confidenceClass) confidenceCell.classList.add(confidenceClass);
        tr.appendChild(confidenceCell);

        const tagsCell = document.createElement('td');
        tagsCell.dataset.title = 'Tags';

        if (row.tags.length) {
          const tagList = document.createElement('div');
          tagList.className = 'tag-list';
          row.tags.forEach((tag) => {
            const tagEl = document.createElement('span');
            tagEl.className = 'tag';
            tagEl.textContent = tag;
            tagList.appendChild(tagEl);
          });
          tagsCell.appendChild(tagList);
        } else {
          tagsCell.textContent = '—';
        }

        tr.appendChild(tagsCell);
        fragment.appendChild(tr);
      });

      tbody.appendChild(fragment);
    };

    const buildSummaryLabel = (select, fallback) => {
      if (!select) return fallback;
      const option = select.selectedOptions?.[0];
      if (!option) return fallback;
      return option.dataset.label || fallback;
    };

    const applyFilter = () => {
      const rows = state.rows;
      if (!rows.length) {
        if (tbody) tbody.innerHTML = '';
        if (table) table.hidden = true;

        setStatus(
          augmentStatusMessage(
            'No source highlights available right now. Check back shortly.'
          ),
          'empty'
        );
        updateSummary([]);
        updateMeta();
        return;
      }

      const searchTerm = state.search.trim().toLowerCase();
      const filtered = rows.filter((row) => {
        if (state.filter !== 'all' && row.typeKey !== state.filter) return false;
        if (
          state.tagFilter !== 'all' &&
          !row.tagsLower.includes(state.tagFilter)
        ) {
          return false;
        }
        if (searchTerm && !row.searchBlob.includes(searchTerm)) return false;
        return true;
      });

      if (!filtered.length) {
        if (tbody) tbody.innerHTML = '';
        if (table) table.hidden = true;

        const summaryParts = [];
        if (state.filter !== 'all')
          summaryParts.push(
            `type: ${buildSummaryLabel(filterSelect, state.filter)}`
          );
        if (state.tagFilter !== 'all')
          summaryParts.push(
            `tag: ${buildSummaryLabel(tagFilterSelect, state.tagFilter)}`
          );
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
      if (table) table.hidden = false;
      updateSummary(limited);
      updateMeta();

      const summaryParts = [];
      if (state.filter !== 'all')
        summaryParts.push(
          `type: ${buildSummaryLabel(filterSelect, state.filter)}`
        );
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
        const previous = state.filter;
        const counts = new Map();

        rows.forEach((row) => {
          const key = row.typeKey || 'unknown';
          if (!counts.has(key)) {
            counts.set(key, {
              label: row.type === '—' ? 'Unknown' : row.type,
              count: 0,
            });
          }
          counts.get(key).count += 1;
        });

        filterSelect.innerHTML = '';
        addOption(filterSelect, 'all', 'All types', rows.length);

        Array.from(counts.entries())
          .sort((a, b) => {
            if (b[1].count !== a[1].count) {
              return b[1].count - a[1].count;
            }
            return a[1].label.localeCompare(b[1].label);
          })
          .forEach(([value, data]) => {
            addOption(filterSelect, value, data.label, data.count);
          });

        const availableValues = new Set(
          Array.from(counts.keys()).concat(['all'])
        );
        filterSelect.value = availableValues.has(previous)
          ? previous
          : 'all';
        state.filter = filterSelect.value;
        filterSelect.disabled = rows.length === 0;
      }

      if (tagFilterSelect) {
        const previousTag = state.tagFilter;
        const tagCounts = new Map();

        rows.forEach((row) => {
          row.tags.forEach((tag, index) => {
            const key = row.tagsLower[index];
            if (!tagCounts.has(key)) {
              tagCounts.set(key, { label: tag, count: 0 });
            }
            tagCounts.get(key).count += 1;
          });
        });

        const uniqueTagCount = tagCounts.size;
        tagFilterSelect.innerHTML = '';
        addOption(tagFilterSelect, 'all', 'All tags', uniqueTagCount);

        Array.from(tagCounts.entries())
          .sort((a, b) => {
            if (b[1].count !== a[1].count) {
              return b[1].count - a[1].count;
            }
            return a[1].label.localeCompare(b[1].label);
          })
          .forEach(([value, data]) => {
            addOption(tagFilterSelect, value, data.label, data.count);
          });

        const availableTags = new Set(
          Array.from(tagCounts.keys()).concat(['all'])
        );
        tagFilterSelect.value = availableTags.has(previousTag)
          ? previousTag
          : 'all';
        state.tagFilter = tagFilterSelect.value;
        tagFilterSelect.disabled = uniqueTagCount === 0;
      }

      if (searchInput) {
        searchInput.disabled = rows.length === 0;
        if (!searchInput.disabled) {
          searchInput.value = state.search;
        }
      }
    };

    const toggleControls = (disabled) => {
      [filterSelect, tagFilterSelect, limitSelect, searchInput, refreshButton]
        .filter(Boolean)
        .forEach((control) => {
          control.disabled = disabled;
        });
    };

    const loadPreview = async ({
      silent = false,
      forceRefresh = false,
    } = {}) => {
      if (!table || !tbody) return;

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
          applyStats(dataset.stats);
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

        setBusy(false);
      }
    };

    // Event wiring
    if (filterSelect) {
      filterSelect.addEventListener('change', (event) => {
        state.filter = event.target.value;
        applyFilter();
      });
    }

    if (tagFilterSelect) {
      tagFilterSelect.addEventListener('change', (event) => {
        state.tagFilter = event.target.value;
        applyFilter();
      });
    }

    if (limitSelect) {
      limitSelect.addEventListener('change', (event) => {
        const parsed = parseInt(event.target.value, 10);
        if (!Number.isNaN(parsed) && parsed > 0) {
          state.limit = parsed;
          loadPreview({ silent: true });
        }
      });
    }

    let searchDebounce = null;
    if (searchInput) {
      searchInput.addEventListener('input', (event) => {
        state.search = event.target.value;
        if (searchDebounce) clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
          applyFilter();
        }, 200);
      });

      searchInput.addEventListener('search', (event) => {
        state.search = event.target.value;
        applyFilter();
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

    subscribeToDataset((dataset) => {
      if (!dataset || !table || !tbody) return;
      if (isCacheOrigin(dataset.origin)) return;

      const previewRows = selectDiverseRows(
        dataset.previewEntries || [],
        state.limit
      );

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
    });

    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        loadPreview({ silent: true, forceRefresh: true });
      });
    }

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
