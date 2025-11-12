(function () {
  const IOC_ROOT = document.body?.dataset.iocRoot || '.';
  const DEFAULT_PREVIEW_LIMIT = 12;
  const PREVIEW_LOOKAHEAD_MULTIPLIER = 12;
  const PREVIEW_CACHE_LIMIT = Math.max(DEFAULT_PREVIEW_LIMIT * PREVIEW_LOOKAHEAD_MULTIPLIER, 240);
  const INDICATORS_JSONL_URL = `${IOC_ROOT}/iocs/latest.jsonl`;
  const INDICATORS_JSON_FALLBACK_URL = `${IOC_ROOT}/iocs/latest.json`;
  const PREVIEW_STREAM_URL = INDICATORS_JSONL_URL;
  const DATASET_STORAGE_KEY = 'swiftioc-dashboard-cache-v1';
  const DATASET_CACHE_TTL = 5 * 60 * 1000;

  const numberFormatter = new Intl.NumberFormat('en-US');
  const formatNumber = (value) => numberFormatter.format(value ?? 0);

  const normaliseString = (value) => (value ?? '').toString().trim();
  const normaliseLower = (value) => normaliseString(value).toLowerCase();
  const coalesceString = (...values) => {
    for (const value of values) {
      const normalised = normaliseString(value);
      if (normalised) {
        return normalised;
      }
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

  const datasetListeners = new Set();
  const subscribeToDataset = (listener) => {
    if (typeof listener !== 'function') {
      return () => {};
    }
    datasetListeners.add(listener);
    return () => {
      datasetListeners.delete(listener);
    };
  };

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
        if (typeof parsed.timestamp !== 'number' || typeof parsed.dataset !== 'object' || !parsed.dataset) {
          target.removeItem(DATASET_STORAGE_KEY);
          return null;
        }
        const dataset = parsed.dataset;
        const age = Date.now() - parsed.timestamp;
        const stale = age > DATASET_CACHE_TTL;
        dataset.fetchedAt = typeof dataset.fetchedAt === 'number' ? dataset.fetchedAt : parsed.timestamp;
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
          fetchedAt: typeof dataset.fetchedAt === 'number' ? dataset.fetchedAt : Date.now(),
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

  const extractTags = (value) => {
    if (!value) return [];
    if (Array.isArray(value)) {
      return uniqueStrings(value);
    }
    if (typeof value === 'string') {
      return uniqueStrings(value.split(/[,;\|]/));
    }
    if (typeof value === 'object') {
      return uniqueStrings(Object.values(value));
    }
    return [];
  };

  const safeParseJson = (line) => {
    try {
      return JSON.parse(line);
    } catch (error) {
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

  const getStatTargets = (name) => document.querySelectorAll(`[data-stat="${name}"]`);
  const setStatText = (name, value) => {
    getStatTargets(name).forEach((element) => {
      element.textContent = value ?? '—';
    });
  };

  const getTableTargets = (name) => Array.from(document.querySelectorAll(`[data-table="${name}"]`));
  const populateTable = (name, rows, emptyMessage) => {
    getTableTargets(name).forEach((tbody) => {
      if (!tbody) return;
      tbody.innerHTML = '';
      if (!rows.length) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        const columnCount = tbody.closest('table')?.querySelectorAll('thead th').length ?? 1;
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

    const normalise = normaliseString;

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

        const source = normalise(row.source);
        const type = normalise(row.type);
        const indicator = normalise(row.indicator);

        if (source) {
          bySource.set(source, (bySource.get(source) || 0) + 1);
        }
        if (type) {
          byType.set(type, (byType.get(type) || 0) + 1);
        }
        if (indicator) {
          indicatorCounts.set(indicator, (indicatorCounts.get(indicator) || 0) + 1);
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
        const sortedSources = Array.from(bySource.entries()).sort((a, b) => b[1] - a[1]);
        const sortedTypes = Array.from(byType.entries()).sort((a, b) => b[1] - a[1]);
        const sortedTags = Array.from(tags.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10);

        const earliestParts = earliestFirstSeen ? isoToParts(earliestFirstSeen.iso) : { date: null, time: null };
        const newestParts = newestFirstSeen ? isoToParts(newestFirstSeen.iso) : { date: null, time: null };

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
        const multiSourceOverlaps = Array.from(indicatorSources.values()).filter((sources) => sources.size > 1).length;

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

  const formatTimestampForDisplay = (value) => {
    const parsed = parseTimestamp(value);
    if (!parsed) {
      const fallback = normaliseString(value);
      return fallback || '—';
    }
    const parts = isoToParts(parsed.iso);
    if (parts.date && parts.time) {
      return `${parts.date} ${parts.time}`;
    }
    if (parts.date) {
      return parts.date;
    }
    return parsed.iso;
  };

  const selectDiverseRows = (rows, limit) => {
    if (!Array.isArray(rows) || !rows.length) return [];
    const max = Math.max(Number(limit) || DEFAULT_PREVIEW_LIMIT, 1);
    const remaining = rows.slice();
    const selected = [];
    const usedTags = new Set();

    while (remaining.length && selected.length < max) {
      let bestIndex = 0;
      let bestNewTags = -1;
      let bestTime = -Infinity;

      remaining.forEach((row, index) => {
        const newTags = row.tagsLower.filter((tag) => !usedTags.has(tag)).length;
        const time = row.firstSeenTime ?? 0;
        if (
          newTags > bestNewTags ||
          (newTags === bestNewTags && time > bestTime) ||
          (newTags === bestNewTags && time === bestTime && index < bestIndex)
        ) {
          bestIndex = index;
          bestNewTags = newTags;
          bestTime = time;
        }
      });

      const [chosen] = remaining.splice(bestIndex, 1);
      selected.push(chosen);
      chosen.tagsLower.forEach((tag) => usedTags.add(tag));
    }

    if (selected.length < max && remaining.length) {
      remaining
        .sort((a, b) => (b.firstSeenTime ?? 0) - (a.firstSeenTime ?? 0))
        .slice(0, max - selected.length)
        .forEach((row) => selected.push(row));
    }

    return selected.sort((a, b) => (b.firstSeenTime ?? 0) - (a.firstSeenTime ?? 0));
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

    return {
      indicator,
      indicatorLower: indicator.toLowerCase(),
      type: typeRaw || '—',
      typeKey: typeRaw ? typeRaw.toLowerCase() : 'unknown',
      source: sourceRaw || '—',
      sourceLower: sourceRaw ? sourceRaw.toLowerCase() : '',
      firstSeen: formatTimestampForDisplay(firstSeenParsed?.iso ?? firstSeenRaw),
      firstSeenTime: firstSeenParsed?.time ?? null,
      confidence: confidenceRaw || '—',
      confidenceLower: confidenceRaw ? confidenceRaw.toLowerCase() : '',
      tags,
      tagsLower: tags.map((tag) => tag.toLowerCase()),
      searchBlob: [indicator, typeRaw, sourceRaw, confidenceRaw, firstSeenRaw, ...tags]
        .filter(Boolean)
        .map((value) => value.toLowerCase())
        .join(' '),
    };
  };

  const confidenceClassFor = (confidence) => {
    const value = normaliseLower(confidence);
    if (!value) return null;
    if (value.includes('high')) return 'confidence-high';
    if (value.includes('medium')) return 'confidence-medium';
    if (value.includes('low')) return 'confidence-low';
    return null;
  };

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
      if (shouldStop) {
        return true;
      }
      return processed >= limit;
    };

    if (!response.body || !response.body.getReader) {
      const text = await response.text();
      const lines = text.split(/\r?\n/);
      for (const line of lines) {
        if (processLine(line)) {
          break;
        }
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
      if (remainder) {
        processLine(remainder);
      }
    } finally {
      if (reader.releaseLock) {
        reader.releaseLock();
      }
    }

    return processed;
  };

  const isCacheOrigin = (origin) => origin === 'cache' || origin === 'cache-stale';

  const computeDatasetKey = (dataset) => {
    if (!dataset || typeof dataset !== 'object') return null;
    if (typeof dataset.fetchedAt === 'number') {
      return `fetched:${dataset.fetchedAt}`;
    }
    if (dataset.stats?.generatedAt) return `generated:${dataset.stats.generatedAt}`;
    if (dataset.stats?.collectionWindow) return `window:${dataset.stats.collectionWindow}`;
    if (dataset.previewEntries?.length) {
      return `preview:${dataset.previewEntries[0].indicatorLower ?? dataset.previewEntries[0].indicator}`;
    }
    return null;
  };

  let lastNotificationKey = null;

  const datasetCache = {
    promise: null,
    refreshing: null,
  };

  const notifyDatasetListeners = (dataset) => {
    if (!dataset || isCacheOrigin(dataset.origin)) return;
    const key = computeDatasetKey(dataset) ?? '__swiftioc-null-key__';
    if (key === lastNotificationKey) return;
    lastNotificationKey = key;
    datasetListeners.forEach((listener) => {
      try {
        listener(dataset);
      } catch (error) {
        console.error('Dataset listener failed', error);
      }
    });
  };

  const wrapDatasetPromise = (promise) => {
    let wrapped;
    wrapped = promise
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
    const response = await fetch(INDICATORS_JSON_FALLBACK_URL, { cache: 'no-store' });
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
        return { stats, previewEntries: fallback.previewEntries, source: fallback.source };
      } catch (fallbackError) {
        console.warn('Failed to augment preview entries via JSON fallback', fallbackError);
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
          if (!datasetCache.refreshing) {
            const refresh = fetchFreshDataset()
              .then((dataset) => {
                if (dataset) {
                  wrapDatasetPromise(Promise.resolve(dataset));
                }
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

  const loadDataset = async ({ previewLimit = DEFAULT_PREVIEW_LIMIT, forceRefresh = false } = {}) => {
    const dataset = await resolveDataset({ forceRefresh });
    const desired = Math.max(Number(previewLimit) || DEFAULT_PREVIEW_LIMIT, 1);
    const previewRows = selectDiverseRows(dataset.previewEntries, desired);
    return {
      dataset,
      previewRows,
    };
  };

  const applyStats = (stats) => {
    setStatText('total-indicators', formatNumber(stats.total));
    setStatText('duplicates-removed', formatNumber(stats.duplicatesRemoved));
    setStatText('active-sources', formatNumber(stats.activeSources));
    setStatText('indicator-types', formatNumber(stats.indicatorTypes));

    const feedsText = `${formatNumber(stats.activeSources)} active source${stats.activeSources === 1 ? '' : 's'}`;
    setStatText('feeds-online', feedsText);

    setStatText('collection-window', stats.collectionWindow ?? '—');
    setStatText('generated-at', stats.generatedAt ?? '—');

    setStatText('earliest-first-seen-date', stats.earliestFirstSeen.date ?? '—');
    setStatText('earliest-first-seen-time', stats.earliestFirstSeen.time ?? '—');
    setStatText('newest-first-seen-date', stats.newestFirstSeen.date ?? '—');
    setStatText('newest-first-seen-time', stats.newestFirstSeen.time ?? '—');
    setStatText('multi-source-overlaps', formatNumber(stats.multiSourceOverlaps));

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

  const initialisePreview = () => {
    const container = document.querySelector('[data-preview-container]');
    if (!container) return;

    const table = container.querySelector('[data-preview-table]');
    const tbody = container.querySelector('[data-preview-body]');
    const statusEl = container.querySelector('[data-preview-status]');
    const filterSelect = container.querySelector('[data-preview-filter]');
    const tagFilterSelect = container.querySelector('[data-preview-tag-filter]');
    const limitSelect = container.querySelector('[data-preview-limit]');
    const searchInput = container.querySelector('[data-preview-search]');
    const refreshButton = container.querySelector('[data-preview-refresh]');

    const state = {
      rows: [],
      filter: 'all',
      tagFilter: 'all',
      search: '',
      limit: DEFAULT_PREVIEW_LIMIT,
      origin: 'network',
      fetchedAt: null,
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
        return `${message} Cached snapshot${describeCacheAge()} is older than our refresh window—fetching fresh data…`;
      }
      if (state.origin === 'cache') {
        return `${message} Cached snapshot${describeCacheAge()}—refreshing data in the background…`;
      }
      return message;
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
        copyButton.setAttribute('aria-label', `Copy indicator ${row.indicator}`);

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

        const confidenceCell = makeCell('Confidence', row.confidence, 'confidence-cell');
        const confidenceClass = confidenceClassFor(row.confidence);
        if (confidenceClass) {
          confidenceCell.classList.add(confidenceClass);
        }
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
        setStatus(augmentStatusMessage('No indicators available right now. Check back shortly.'), 'empty');
        return;
      }

      const searchTerm = state.search.trim().toLowerCase();
      const filtered = rows.filter((row) => {
        if (state.filter !== 'all' && row.typeKey !== state.filter) {
          return false;
        }
        if (state.tagFilter !== 'all' && !row.tagsLower.includes(state.tagFilter)) {
          return false;
        }
        if (searchTerm && !row.searchBlob.includes(searchTerm)) {
          return false;
        }
        return true;
      });

      if (!filtered.length) {
        if (tbody) tbody.innerHTML = '';
        if (table) table.hidden = true;
        const summaryParts = [];
        if (state.filter !== 'all') summaryParts.push(`type: ${buildSummaryLabel(filterSelect, state.filter)}`);
        if (state.tagFilter !== 'all') summaryParts.push(`tag: ${buildSummaryLabel(tagFilterSelect, state.tagFilter)}`);
        if (searchTerm) summaryParts.push(`search: “${state.search.trim()}”`);
        const qualifier = summaryParts.length ? ` for ${summaryParts.join(', ')}` : '';
        setStatus(
          augmentStatusMessage(
            `No indicators match the current filters${qualifier}. Adjust filters or refresh the feed.`
          ),
          'empty'
        );
        return;
      }

      renderRows(filtered);
      if (table) table.hidden = false;
      const summaryParts = [];
      if (state.filter !== 'all') summaryParts.push(`type: ${buildSummaryLabel(filterSelect, state.filter)}`);
      if (state.tagFilter !== 'all') summaryParts.push(`tag: ${buildSummaryLabel(tagFilterSelect, state.tagFilter)}`);
      if (searchTerm) summaryParts.push(`search: “${state.search.trim()}”`);
      const qualifier = summaryParts.length ? ` (${summaryParts.join(', ')})` : '';
      setStatus(
        augmentStatusMessage(`Showing ${filtered.length} of ${rows.length} curated indicators${qualifier}.`),
        'ready'
      );
    };

    const addOption = (select, value, label, count) => {
      if (!select) return;
      const option = document.createElement('option');
      option.value = value;
      option.textContent = count != null ? `${label} (${count})` : label;
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
            counts.set(key, { label: row.type === '—' ? 'Unknown' : row.type, count: 0 });
          }
          counts.get(key).count += 1;
        });

        filterSelect.innerHTML = '';
        addOption(filterSelect, 'all', 'All types', rows.length);
        Array.from(counts.entries())
          .sort((a, b) => {
            if (b[1].count !== a[1].count) return b[1].count - a[1].count;
            return a[1].label.localeCompare(b[1].label);
          })
          .forEach(([value, data]) => {
            addOption(filterSelect, value, data.label, data.count);
          });

        const availableValues = new Set(Array.from(counts.keys()).concat(['all']));
        filterSelect.value = availableValues.has(previous) ? previous : 'all';
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
            if (b[1].count !== a[1].count) return b[1].count - a[1].count;
            return a[1].label.localeCompare(b[1].label);
          })
          .forEach(([value, data]) => {
            addOption(tagFilterSelect, value, data.label, data.count);
          });

        const availableTags = new Set(Array.from(tagCounts.keys()).concat(['all']));
        tagFilterSelect.value = availableTags.has(previousTag) ? previousTag : 'all';
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

    const loadPreview = async ({ silent = false, forceRefresh = false } = {}) => {
      if (!table || !tbody) return;

      setBusy(true);
      table.hidden = true;
      tbody.innerHTML = '';
      setStatus(silent ? 'Refreshing live data…' : 'Loading live data…', 'loading');

      const controls = [filterSelect, tagFilterSelect, limitSelect, searchInput, refreshButton];
      controls.forEach((control) => {
        if (control) control.disabled = true;
      });

      try {
        const { dataset, previewRows } = await loadDataset({
          previewLimit: state.limit,
          forceRefresh,
        });
        state.rows = previewRows;
        state.origin = dataset.origin || 'network';
        state.fetchedAt = typeof dataset.fetchedAt === 'number' ? dataset.fetchedAt : null;
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
        if (tbody) tbody.innerHTML = '';
        setStatus('Unable to load the preview. Try again shortly or download the full feed below.', 'error');
      } finally {
        controls.forEach((control) => {
          if (!control) return;
          if (control === filterSelect) {
            control.disabled = state.rows.length === 0;
          } else if (control === tagFilterSelect) {
            control.disabled =
              state.rows.length === 0 || !tagFilterSelect.options || tagFilterSelect.options.length <= 1;
          } else if (control === searchInput) {
            control.disabled = state.rows.length === 0;
            if (!control.disabled) {
              control.value = state.search;
            }
          } else {
            control.disabled = false;
          }
        });
        setBusy(false);
      }
    };

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
      const previewRows = selectDiverseRows(dataset.previewEntries, state.limit);
      state.rows = previewRows;
      state.origin = dataset.origin || 'network';
      state.fetchedAt = typeof dataset.fetchedAt === 'number' ? dataset.fetchedAt : null;
      populateFilterOptions(previewRows);
      applyFilter();
    });

    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        loadPreview({ silent: true, forceRefresh: true });
      });
    }

    const triggerInitialLoad = () => {
      loadPreview();
    };

    const hasIntersectionObserver = typeof window !== 'undefined' && 'IntersectionObserver' in window;
    if (hasIntersectionObserver) {
      const observer = new IntersectionObserver(
        (entries) => {
          if (entries.some((entry) => entry.isIntersecting)) {
            observer.disconnect();
            triggerInitialLoad();
          }
        },
        { rootMargin: '0px 0px 200px 0px' }
      );
      observer.observe(container);
    } else {
      triggerInitialLoad();
    }
  };

  loadStats();
  initialisePreview();
})();
