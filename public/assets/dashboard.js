(function () {
  const PREVIEW_LIMIT = 12;
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
      const rows = await readPreview('iocs/latest.jsonl', PREVIEW_LIMIT);
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
})();
