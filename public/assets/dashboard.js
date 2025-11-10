(function () {
  const IOC_ROOT = document.body?.dataset.iocRoot || '.';
  const PREVIEW_LIMIT = 12;
  const INDICATORS_JSON_URL = `${IOC_ROOT}/iocs/latest.json`;
  const PREVIEW_STREAM_URL = `${IOC_ROOT}/iocs/latest.jsonl`;

  const numberFormatter = new Intl.NumberFormat('en-US');
  const formatNumber = (value) => numberFormatter.format(value ?? 0);

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

  const computeStats = (indicators) => {
    const bySource = new Map();
    const byType = new Map();
    const tags = new Map();
    const indicatorSources = new Map();
    let earliestFirstSeen = null;
    let newestFirstSeen = null;
    let generatedTimestamp = null;

    indicators.forEach((row) => {
      const source = (row.source || '').toString().trim();
      const type = (row.type || '').toString().trim();
      const indicator = (row.indicator || '').toString().trim();

      if (source) {
        bySource.set(source, (bySource.get(source) || 0) + 1);
      }
      if (type) {
        byType.set(type, (byType.get(type) || 0) + 1);
      }
      if (indicator) {
        if (!indicatorSources.has(indicator)) {
          indicatorSources.set(indicator, new Set());
        }
        if (source) {
          indicatorSources.get(indicator).add(source);
        }
      }

      const firstSeen = parseTimestamp(row.first_seen || row.firstSeen);
      const lastSeen = parseTimestamp(row.last_seen || row.lastSeen);

      if (firstSeen) {
        if (!earliestFirstSeen || firstSeen.time < earliestFirstSeen.time) {
          earliestFirstSeen = firstSeen;
        }
        if (!newestFirstSeen || firstSeen.time > newestFirstSeen.time) {
          newestFirstSeen = firstSeen;
        }
        if (!generatedTimestamp || firstSeen.time > generatedTimestamp.time) {
          generatedTimestamp = firstSeen;
        }
      }
      if (lastSeen && (!generatedTimestamp || lastSeen.time > generatedTimestamp.time)) {
        generatedTimestamp = lastSeen;
      }

      const rowTags = (row.tags || '')
        .toString()
        .split(',')
        .map((tag) => tag.trim())
        .filter(Boolean);
      rowTags.forEach((tag) => {
        tags.set(tag, (tags.get(tag) || 0) + 1);
      });
    });

    const total = indicators.length;
    const uniqueIndicators = indicatorSources.size;
    const duplicatesRemoved = Math.max(total - uniqueIndicators, 0);
    const multiSourceOverlaps = Array.from(indicatorSources.values()).filter((sources) => sources.size > 1).length;

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
      generatedAt: generatedTimestamp?.iso || null,
      collectionWindow,
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

  const loadStats = async () => {
    try {
      const response = await fetch(INDICATORS_JSON_URL, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`Unable to fetch indicator summary (${response.status})`);
      }
      const indicators = await response.json();
      const stats = computeStats(Array.isArray(indicators) ? indicators : []);
      applyStats(stats);
    } catch (error) {
      console.error('Failed to load indicator statistics', error);
      setStatText('generated-at', 'Unavailable');
      populateTable('sources', [], 'Source data unavailable.');
      populateTable('types', [], 'Indicator type data unavailable.');
      populateTable('tags', [], 'Tag data unavailable.');
    }
  };

  const initialisePreview = () => {
    const container = document.querySelector('[data-preview-container]');
    if (!container) return;

    const table = container.querySelector('[data-preview-table]');
    const tbody = container.querySelector('[data-preview-body]');
    const statusEl = container.querySelector('[data-preview-status]');
    const filterSelect = container.querySelector('[data-preview-filter]');
    const refreshButton = container.querySelector('[data-preview-refresh]');

    const state = {
      rows: [],
      filter: 'all',
    };

    const normaliseType = (value) => (value || '').toString().trim();

    const setStatus = (message, mode = 'idle') => {
      if (!statusEl) return;
      statusEl.textContent = message;
      statusEl.dataset.state = mode;
    };

    const setBusy = (busy) => {
      container.setAttribute('aria-busy', busy ? 'true' : 'false');
    };

    const safeParse = (line) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        console.warn('Skipping malformed preview row', error);
        return null;
      }
    };

    const readPreview = async (url, limit) => {
      const response = await fetch(url, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`Failed to fetch preview (${response.status})`);
      }

      const takeFromBuffer = (buffer, rows) => {
        const lines = buffer.split(/\r?\n/);
        const remainder = lines.pop() ?? '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          const parsed = safeParse(trimmed);
          if (parsed) {
            rows.push(parsed);
            if (rows.length >= limit) {
              break;
            }
          }
        }
        return remainder;
      };

      const rows = [];

      if (!response.body || !response.body.getReader) {
        const text = await response.text();
        takeFromBuffer(text, rows);
        return rows.slice(0, limit);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      try {
        while (rows.length < limit) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          buffer = takeFromBuffer(buffer, rows);
          if (rows.length >= limit) {
            await reader.cancel().catch(() => {});
            break;
          }
        }

        if (rows.length < limit && buffer.trim()) {
          const parsed = safeParse(buffer.trim());
          if (parsed) {
            rows.push(parsed);
          }
        }
      } finally {
        if (reader.releaseLock) {
          reader.releaseLock();
        }
      }

      return rows.slice(0, limit);
    };

    const renderRows = (rows) => {
      if (!tbody) return;
      tbody.innerHTML = '';

      const fragment = document.createDocumentFragment();
      rows.forEach((row) => {
        const tr = document.createElement('tr');

        const makeCell = (title, value, className) => {
          const td = document.createElement('td');
          td.dataset.title = title;
          if (className) td.classList.add(className);
          td.textContent = value;
          return td;
        };

        const indicatorCell = document.createElement('td');
        indicatorCell.dataset.title = 'Indicator';
        indicatorCell.classList.add('indicator-cell');
        indicatorCell.textContent = row.indicator ?? '';
        tr.appendChild(indicatorCell);

        tr.appendChild(makeCell('Type', row.type ?? '—'));
        tr.appendChild(makeCell('Source', row.source ?? '—'));

        const firstSeenCell = makeCell('First seen', row.first_seen ?? '—');
        tr.appendChild(firstSeenCell);

        const confidenceCell = makeCell('Confidence', row.confidence ?? '—', 'confidence-cell');
        const confidence = normaliseType(row.confidence).toLowerCase();
        if (confidence) {
          confidenceCell.classList.add(`confidence-${confidence}`);
        }
        tr.appendChild(confidenceCell);

        const tagsCell = document.createElement('td');
        tagsCell.dataset.title = 'Tags';
        const tags = (row.tags || '')
          .toString()
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean)
          .slice(0, 4);
        if (tags.length) {
          const tagList = document.createElement('div');
          tagList.className = 'tag-list';
          tags.forEach((tag) => {
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

    const applyFilter = () => {
      const filter = state.filter;
      const rows = state.rows;
      const filtered =
        filter === 'all' ? rows : rows.filter((row) => normaliseType(row.type).toLowerCase() === filter);

      if (!filtered.length) {
        if (tbody) tbody.innerHTML = '';
        table.hidden = true;
        setStatus('No indicators match this filter yet.', 'empty');
        return;
      }

      renderRows(filtered);
      table.hidden = false;
      const summary = filter === 'all' ? '' : ` (type: ${filter.toUpperCase()})`;
      setStatus(`Showing ${filtered.length} of ${rows.length} recent indicators${summary}.`, 'ready');
    };

    const populateFilterOptions = (rows) => {
      if (!filterSelect) return;
      const options = new Set();
      rows.forEach((row) => {
        const type = normaliseType(row.type).toLowerCase();
        if (type) options.add(type);
      });

      const orderedValues = ['all', ...Array.from(options).sort()];

      filterSelect.innerHTML = '';
      orderedValues.forEach((value) => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value === 'all' ? 'All types' : value;
        filterSelect.appendChild(option);
      });
      filterSelect.value = 'all';
      filterSelect.disabled = false;
    };

    const loadPreview = async (silent = false) => {
      setBusy(true);
      table.hidden = true;
      if (tbody) {
        tbody.innerHTML = '';
      }
      setStatus(silent ? 'Refreshing live data…' : 'Loading live data…', 'loading');

      if (filterSelect) filterSelect.disabled = true;
      if (refreshButton) refreshButton.disabled = true;

      try {
        const rows = await readPreview(PREVIEW_STREAM_URL, PREVIEW_LIMIT);
        state.rows = rows;
        state.filter = 'all';

        if (!rows.length) {
          setStatus('No indicators available right now. Check back shortly.', 'empty');
          return;
        }

        populateFilterOptions(rows);
        applyFilter();
      } catch (error) {
        console.error('Unable to load live preview', error);
        setStatus('Unable to load the preview. Try again shortly or download the full feed below.', 'error');
      } finally {
        if (filterSelect) filterSelect.disabled = state.rows.length === 0;
        if (refreshButton) refreshButton.disabled = false;
        setBusy(false);
      }
    };

    if (filterSelect) {
      filterSelect.addEventListener('change', (event) => {
        state.filter = event.target.value;
        applyFilter();
      });
    }

    if (refreshButton) {
      refreshButton.addEventListener('click', () => {
        loadPreview(true);
      });
    }

    loadPreview();
  };

  loadStats();
  initialisePreview();
})();
