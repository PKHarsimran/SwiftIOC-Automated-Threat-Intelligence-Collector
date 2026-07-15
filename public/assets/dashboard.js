(function () {
  'use strict';

  const dashboardCore = window.SwiftIOCCore || null;

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

  // Compact, strongest-first feed produced specifically for the dashboard
  // (~100 KB). The full latest.jsonl runs to many MB, so it is only a
  // fallback for deployments that predate dashboard.jsonl.
  const DASHBOARD_FEED_URL = resolveIocUrl('iocs/dashboard.jsonl');
  const INDICATORS_JSONL_URL = resolveIocUrl('iocs/latest.jsonl');
  const INDICATORS_JSON_FALLBACK_URL = resolveIocUrl('iocs/latest.json');
  // Tiny JSON of full-feed aggregates (totals, score bands, per-source/type/
  // tag counts) written by the collector each run.
  const RUN_DIAG_URL = resolveIocUrl('diagnostics/run.json');
  // Rolling per-run history (capped) for the trend sparkline.
  const HISTORY_URL = resolveIocUrl('diagnostics/history.json');

  const DATASET_STORAGE_KEY = 'swiftioc-dashboard-cache-v2';
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

  // Undo defang_min() from the collector (hxxp[s]:// -> http[s]://, [.] -> .)
  // so a user can paste either a defanged or a raw indicator into search.
  const refang = dashboardCore?.refang || ((value) =>
    normaliseString(value)
      .replace(/hxxps:\/\//gi, 'https://')
      .replace(/hxxp:\/\//gi, 'http://')
      .replace(/\[\.\]/g, '.'));

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

  const showToast = (message) => {
    const toast = qs('[data-toast]');
    if (!toast) return;
    toast.textContent = message;
    toast.hidden = false;
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => {
      toast.hidden = true;
    }, 2400);
  };

  const copyToClipboard = async (value) => {
    const text = normaliseString(value);
    if (!text) return false;
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    const success = document.execCommand('copy');
    textarea.remove();
    return success;
  };

  const safeHttpUrl = (value) => {
    const text = normaliseString(value);
    if (!text) return null;
    try {
      const url = new URL(text);
      return ['http:', 'https:'].includes(url.protocol) ? url.toString() : null;
    } catch (error) {
      return null;
    }
  };

  const downloadJson = (row) => {
    const payload = row?.raw && typeof row.raw === 'object' ? row.raw : row;
    const blob = new Blob([JSON.stringify(payload, null, 2) + '\n'], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const safeType = normaliseLower(row?.type).replace(/[^a-z0-9_-]+/g, '-') || 'ioc';
    anchor.href = url;
    anchor.download = 'swiftioc-' + safeType + '.json';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  };

  // Compact label for a possibly multi-source row: "feodo +2".
  const primarySourceLabel = (row) => {
    if (!row) return 'unknown';
    const list = Array.isArray(row.sourceList) ? row.sourceList : [];
    if (!list.length) return row.source || 'unknown';
    if (list.length === 1) return list[0];
    return `${list[0]} +${list.length - 1}`;
  };

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
      { amount: 60, unit: 'second' },
      { amount: 60, unit: 'minute' },
      { amount: 24, unit: 'hour' },
      { amount: 7, unit: 'day' },
      { amount: 4.34524, unit: 'week' },
      { amount: 12, unit: 'month' },
      { amount: Infinity, unit: 'year' },
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

    // Timestamps throughout the dashboard are normalised to seconds.
    // Ensure we convert to milliseconds for Date() to avoid 1970-era fallbacks
    // when recent epoch seconds are mistakenly treated as milliseconds.
    const millis = timestamp > 1e12 ? timestamp : timestamp * 1000;
    const date = new Date(millis);
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

  const scoreBandLabel = (row) => {
    if (typeof row?.score === 'number') {
      if (row.score >= 80) return 'High';
      if (row.score >= 60) return 'Elevated';
      if (row.score >= 40) return 'Moderate';
      return 'Aging';
    }
    const rank = confidenceRankForRow(row);
    if (rank >= 3) return 'High';
    if (rank === 2) return 'Moderate';
    if (rank === 1) return 'Low';
    return 'Unscored';
  };

  const explainScore = (row) => {
    const sourceText = (row?.sourceCount || 0) >= 2
      ? 'confirmed by ' + row.sourceCount + ' independent sources'
      : 'reported by one source';
    const age = formatRelativeTimeFromNow(row?.bestTimestamp);
    const freshnessText = age ? ' and last seen ' + age : '';
    if (typeof row?.score === 'number') {
      return scoreBandLabel(row) + ' confidence: ' + sourceText + freshnessText +
        '. Score combines source confidence, corroboration, and freshness.';
    }
    return scoreBandLabel(row) + ' confidence from the source; a numeric freshness score is not available for this legacy row.';
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
    let corroborated = 0;
    let highScore = 0;
    let highConfidence = 0;
    let scoreSum = 0;
    let scoredCount = 0;
    // Score bands for the distribution bar: critical / high / medium / low.
    const scoreBands = { critical: 0, high: 0, medium: 0, low: 0 };
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

      // Multi-source rows carry comma-separated feeds; count each feed as a
      // distinct source instead of treating "feodo,threatfox" as one.
      const sourceParts = Array.isArray(row.sourceList)
        ? row.sourceList
        : uniqueStrings(source.split(','));
      sourceParts.forEach((part) => {
        const key = normaliseLower(part);
        if (key) sources.add(key);
      });

      const multiSource = sourceParts.length >= 2;
      if (multiSource) {
        corroborated += 1;
      }

      const legacyConfidenceRank = confidenceRankForValue(row.confidence);

      if (typeof row.score === 'number') {
        scoreSum += row.score;
        scoredCount += 1;
        if (row.score >= 80) highScore += 1;
        if (row.score >= 80) scoreBands.critical += 1;
        else if (row.score >= 60) scoreBands.high += 1;
        else if (row.score >= 40) scoreBands.medium += 1;
        else scoreBands.low += 1;
      } else if (legacyConfidenceRank >= 3) {
        highScore += 1;
        scoreBands.critical += 1;
      } else if (legacyConfidenceRank === 2) {
        scoreBands.high += 1;
      } else if (legacyConfidenceRank === 1) {
        scoreBands.medium += 1;
      }

      // Block-ready: high score OR confirmed by multiple independent sources.
      if (
        (typeof row.score === 'number' && row.score >= 80) ||
        (typeof row.score !== 'number' && legacyConfidenceRank >= 3) ||
        multiSource
      ) {
        highConfidence += 1;
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
        corroborated,
        highScore,
        highConfidence,
        scoreBands,
        avgScore: scoredCount > 0 ? Math.round(scoreSum / scoredCount) : null,
        hasScores: scoredCount > 0,
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

      // Credit each feed in a comma-separated multi-source value.
      const sourceParts = Array.isArray(row.sourceList)
        ? row.sourceList
        : uniqueStrings(source.split(','));
      sourceParts.forEach((part) => {
        bySource.set(part, (bySource.get(part) || 0) + 1);
      });

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

      const max = entries.reduce((m, [, count]) => Math.max(m, count), 0) || 1;
      return entries
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .map(([label, count]) => {
          const pct = (count / total) * 100;
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
              value: `${pct.toFixed(1)}%`,
              numeric: true,
              // Bar width is relative to the largest row so small feeds stay
              // visible; the label still shows the true share of total.
              bar: (count / max) * 100,
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

  // Convert a {name: count} object (from run.json) into the same row shape
  // the table aggregators produce. Returns null when the object is unusable
  // so callers can fall back to subset-derived rows.
  const countsObjectToRows = (obj, labelKey) => {
    if (!obj || typeof obj !== 'object') return null;
    const entries = Object.entries(obj).filter(
      ([, count]) => typeof count === 'number'
    );
    if (!entries.length) return null;
    const total = entries.reduce((sum, [, count]) => sum + count, 0) || 1;
    const max = entries.reduce((m, [, count]) => Math.max(m, count), 0) || 1;
    return entries
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([label, count]) => {
        const pct = (count / total) * 100;
        return [
          { title: labelKey, value: label },
          { title: 'Count', value: formatNumber(count), numeric: true },
          {
            title: 'Share',
            value: `${pct.toFixed(1)}%`,
            numeric: true,
            bar: (count / max) * 100,
          },
        ];
      });
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
        cells.forEach((cell, index) => {
          const td = document.createElement(index === 0 ? 'th' : 'td');
          if (index === 0) td.scope = 'row';
          td.dataset.title = cell.title;
          if (cell.numeric) td.classList.add('numeric');
          if (typeof cell.bar === 'number') {
            // Share cell: proportion bar behind a right-aligned value.
            td.classList.add('has-bar');
            const fill = document.createElement('span');
            fill.className = 'cell-bar';
            fill.style.width = `${Math.max(2, Math.min(100, cell.bar))}%`;
            const val = document.createElement('span');
            val.className = 'cell-bar-value';
            val.textContent = cell.value;
            td.append(fill, val);
          } else {
            td.textContent = cell.value;
          }
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });
    });
  };

  /* ==========================================================================
   *  MOBILE TABLE LIMITER
   * ========================================================================= */

  const TABLE_MOBILE_BREAKPOINT = 760;
  const TABLE_MOBILE_PREVIEW_LIMIT = 6;
  const tableStates = new Map();

  const isMobileTableViewport = () =>
    typeof window !== 'undefined' &&
    window.matchMedia(`(max-width: ${TABLE_MOBILE_BREAKPOINT}px)`).matches;

  const clampTableRows = (name) => {
    const state = tableStates.get(name) || { expanded: false };
    const isMobile = isMobileTableViewport();
    const limit = TABLE_MOBILE_PREVIEW_LIMIT;

    const rows = getTableTargets(name).flatMap((tbody) =>
      Array.from(tbody?.querySelectorAll('tr') || [])
    );

    const shouldHideButton = !isMobile || rows.length <= limit;

    rows.forEach((tr, index) => {
      const hide = isMobile && !state.expanded && index >= limit;
      tr.hidden = hide;
      tr.classList.toggle('is-collapsed', hide);
    });

    qsa(`[data-table-toggle="${name}"]`).forEach((button) => {
      if (shouldHideButton) {
        button.hidden = true;
        return;
      }

      button.hidden = false;
      button.setAttribute('aria-expanded', state.expanded ? 'true' : 'false');

      const remaining = Math.max(rows.length - limit, 0);
      const collapsedLabel =
        remaining > 0
          ? `Show all ${rows.length} entries`
          : 'Show full table';
      const expandedLabel = `Collapse to top ${limit}`;

      button.textContent = state.expanded ? expandedLabel : collapsedLabel;
    });
  };

  const initialiseTableToggles = () => {
    qsa('[data-table-toggle]').forEach((button) => {
      const name = button?.dataset?.tableToggle;
      if (!name) return;

      if (!tableStates.has(name)) {
        tableStates.set(name, { expanded: false });
      }

      button.addEventListener('click', () => {
        const current = tableStates.get(name) || { expanded: false };
        tableStates.set(name, { expanded: !current.expanded });
        clampTableRows(name);
      });
    });

    const mediaQuery = window.matchMedia(
      `(max-width: ${TABLE_MOBILE_BREAKPOINT}px)`
    );
    mediaQuery.addEventListener('change', () => {
      ['sources', 'types', 'tags'].forEach((name) => clampTableRows(name));
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
      row.confidenceLevel
    );

    // Numeric 0-100 relevance score emitted by the collector (confidence base
    // + cross-source corroboration bonus, decayed by age). First-class: this
    // is the primary ranking signal when present.
    const parseScore = (value) => {
      if (typeof value === 'number' && Number.isFinite(value)) {
        return clamp(Math.round(value), 0, 100);
      }
      const numeric = Number(normaliseString(value));
      if (Number.isFinite(numeric) && numeric > 0) {
        return clamp(Math.round(numeric), 0, 100);
      }
      return null;
    };
    const score = parseScore(row.score);

    // The source field accumulates comma-separated feeds as the living feed
    // merges runs; each independent feed corroborates the indicator.
    const sourceList = uniqueStrings((sourceRaw || '').split(','));
    const sourceCount = sourceList.length;

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

    const firstSeenParsed = parseTimestamp(firstSeen);
    const lastSeenParsed = parseTimestamp(lastSeen);
    const bestTimestamp = lastSeenParsed?.time ?? firstSeenParsed?.time ?? null;

    const firstSeenDisplay = formatTimestampForDisplay(firstSeen ?? lastSeen);
    const lastSeenDisplay = formatTimestampForDisplay(lastSeen ?? firstSeen);
    const reference = safeHttpUrl(
      row.reference ?? row.reference_url ?? row.ref_url ?? row.source_url
    );
    const context = normaliseString(row.context ?? row.description ?? row.comment);
    const tlp = normaliseString(row.tlp ?? row.marking ?? row.traffic_light_protocol);

    const normalised = {
      indicator,
      type: typeRaw || 'unknown',
      source: sourceRaw || 'unknown',
      sourceList,
      sourceCount,
      score,
      confidence,
      confidenceRank:
        score != null
          ? confidenceRankForValue(score)
          : confidenceRankForValue(confidence),
      tags,
      tagsLower,
      firstSeen,
      lastSeen,
      firstSeenDisplay,
      lastSeenDisplay,
      bestTimestamp,
      reference,
      context,
      tlp,
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
    if (!dataset) return;
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

  const derivePreviewTimestamps = (row) => {
    if (!row || typeof row !== 'object') return { recency: null, lastSeen: null };
    if (row.previewTimestamps) return row.previewTimestamps;

    const lastSeenParsed = parseTimestamp(row.lastSeen);
    const firstSeenParsed = parseTimestamp(row.firstSeen);

    const recency = firstSeenParsed?.time ?? lastSeenParsed?.time ?? null;

    row.previewTimestamps = {
      recency,
      lastSeen: lastSeenParsed?.time ?? null,
    };
    return row.previewTimestamps;
  };

  const selectPreviewRows = (rows, limit) => {
    if (!Array.isArray(rows) || rows.length === 0 || limit <= 0) return [];

    const groups = new Map();
    rows.forEach((row) => {
      const key = normaliseLower(row.source) || 'unknown';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(row);
    });

    const compareRows = (a, b) => {
      // Primary signal: the collector's 0-100 score (confidence +
      // cross-source corroboration, decayed by age). Falls back to the
      // coarse confidence rank for feeds without scores.
      const scoreA = typeof a.score === 'number' ? a.score : -1;
      const scoreB = typeof b.score === 'number' ? b.score : -1;
      if (scoreA !== scoreB) return scoreB - scoreA;

      const corroborationDiff = (b.sourceCount || 0) - (a.sourceCount || 0);
      if (corroborationDiff !== 0) return corroborationDiff;

      const confidenceDiff = confidenceRankForRow(b) - confidenceRankForRow(a);
      if (confidenceDiff !== 0) return confidenceDiff;

      const timestampsA = derivePreviewTimestamps(a);
      const timestampsB = derivePreviewTimestamps(b);

      const recencyA = timestampsA.recency ?? -Infinity;
      const recencyB = timestampsB.recency ?? -Infinity;
      if (recencyA !== recencyB) return recencyB - recencyA;

      const lastSeenA = timestampsA.lastSeen ?? -Infinity;
      const lastSeenB = timestampsB.lastSeen ?? -Infinity;
      if (lastSeenA !== lastSeenB) return lastSeenB - lastSeenA;

      const duplicateDiff = Number(a.isDuplicate) - Number(b.isDuplicate);
      if (duplicateDiff !== 0) return duplicateDiff;

      return (a.indicator || '').localeCompare(b.indicator || '');
    };

    groups.forEach((list) => list.sort(compareRows));

    const orderedGroups = Array.from(groups.values()).sort((a, b) =>
      compareRows(a[0], b[0])
    );

    const selected = [];
    while (selected.length < limit && orderedGroups.length) {
      for (let i = 0; i < orderedGroups.length && selected.length < limit; i += 1) {
        const group = orderedGroups[i];
        if (!group.length) continue;
        selected.push(group.shift());
        if (!group.length) {
          orderedGroups.splice(i, 1);
          i -= 1;
        }
      }
    }

    return selected;
  };

  const loadFromStorage = () => {
    try {
      const raw = localStorage.getItem(DATASET_STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      const { entries, fetchedAt, stats, diag } = parsed;
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
        diag: diag || null,
        fetchedAt,
      };
    } catch (error) {
      console.warn('Failed to load cache', error);
      return null;
    }
  };

  const saveToStorage = (dataset) => {
    try {
      const { entries, stats, diag, fetchedAt } = dataset;
      if (!Array.isArray(entries)) return;
      localStorage.setItem(
        DATASET_STORAGE_KEY,
        JSON.stringify({
          entries,
          stats,
          diag: diag || null,
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
      // The compact dashboard feed first: ~2% of the full feed's size.
      return await streamJsonLines(DASHBOARD_FEED_URL, previewLimit);
    } catch (error) {
      console.warn('dashboard.jsonl unavailable, falling back to full feed', error);
    }
    try {
      return await streamJsonLines(INDICATORS_JSONL_URL, previewLimit);
    } catch (error) {
      console.warn('JSONL request failed, falling back to JSON', error);
      return fetchJsonDataset(INDICATORS_JSON_FALLBACK_URL, previewLimit);
    }
  };

  // Full-feed aggregates from the collector run: totals, score bands,
  // per-source/type/tag counts. Lets the dashboard show accurate global
  // numbers while only downloading the compact feed. Null when unavailable.
  const fetchRunDiag = async () => {
    try {
      const response = await fetch(RUN_DIAG_URL, {
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) return null;
      const data = await response.json();
      return data && typeof data === 'object' ? data : null;
    } catch (error) {
      console.warn('run.json unavailable', error);
      return null;
    }
  };

  const resolveDataset = async ({ forceRefresh = false } = {}) => {
    const wrapDatasetPromise = (promise) =>
      promise
        .then((dataset) => {
          notifyDatasetListeners(dataset);
          return dataset;
        })
        .catch((error) => {
          datasetCache.promise = null;
          throw error;
        });

    const fetchFreshDataset = async () => {
      const [{ entries }, diag] = await Promise.all([
        fetchDataset(PREVIEW_CACHE_LIMIT),
        fetchRunDiag(),
      ]);

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

      // Prefer the collector's full-feed aggregates over numbers derived from
      // the compact feed subset.
      if (diag) {
        if (typeof diag.total === 'number') stats.total = diag.total;
        if (typeof diag.high_confidence_total === 'number') {
          stats.highConfidence = diag.high_confidence_total;
          stats.highScore = diag.high_confidence_total;
        }
        if (typeof diag.corroborated_total === 'number') {
          stats.corroborated = diag.corroborated_total;
        }
        if (typeof diag.score_avg === 'number') {
          stats.avgScore = Math.round(diag.score_avg);
          stats.hasScores = true;
        }
        if (diag.score_bands && typeof diag.score_bands === 'object') {
          stats.scoreBands = diag.score_bands;
        }
        if (typeof diag.duplicates_removed === 'number') {
          stats.duplicatesRemoved = diag.duplicates_removed;
        }
        if (diag.counts && typeof diag.counts === 'object') {
          stats.activeSources = Object.keys(diag.counts).length;
        }
        if (diag.type_counts && typeof diag.type_counts === 'object') {
          stats.indicatorTypes = Object.keys(diag.type_counts).length;
        }
      }

      const previewEntriesNormalised = selectPreviewRows(
        normalisedEntries,
        PREVIEW_CACHE_LIMIT
      );

      const dataset = {
        origin: 'network',
        entries: normalisedEntries,
        previewEntries: previewEntriesNormalised,
        stats,
        diag,
        fetchedAt: Date.now(),
        sourcesTable:
          countsObjectToRows(diag?.counts, 'Source') ||
          tableAggregators.toSourceRows(),
        typesTable:
          countsObjectToRows(diag?.type_counts, 'Type') ||
          tableAggregators.toTypeRows(),
        tagsTable:
          countsObjectToRows(diag?.tag_counts, 'Tag') ||
          tableAggregators.toTagRows(),
      };

      saveToStorage(dataset);
      return dataset;
    };

    if (forceRefresh) {
      if (!datasetCache.refreshing) {
        const refresh = wrapDatasetPromise(fetchFreshDataset())
          .then((fresh) => {
            datasetCache.promise = Promise.resolve(fresh);
            return fresh;
          })
          .finally(() => {
            if (datasetCache.refreshing === refresh) {
              datasetCache.refreshing = null;
            }
          });
        datasetCache.refreshing = refresh;
      }
      return datasetCache.refreshing;
    }

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
        const diag = cached.diag || null;
        const dataset = {
          origin: cached.origin,
          entries: normalisedEntries,
          previewEntries: selectPreviewRows(
            normalisedEntries,
            PREVIEW_CACHE_LIMIT
          ),
          stats,
          diag,
          fetchedAt: cached.fetchedAt,
          sourcesTable:
            countsObjectToRows(diag?.counts, 'Source') ||
            tableAggregators.toSourceRows(),
          typesTable:
            countsObjectToRows(diag?.type_counts, 'Type') ||
            tableAggregators.toTypeRows(),
          tagsTable:
            countsObjectToRows(diag?.tag_counts, 'Tag') ||
            tableAggregators.toTagRows(),
        };

        datasetCache.promise = Promise.resolve(dataset);

        if (!datasetCache.refreshing) {
          const refresh = wrapDatasetPromise(fetchFreshDataset())
            .then((fresh) => {
              datasetCache.promise = Promise.resolve(fresh);
              return fresh;
            })
            .catch((error) => {
              console.warn('Background refresh from cache failed', error);
              return null;
            })
            .finally(() => {
              if (datasetCache.refreshing === refresh) {
                datasetCache.refreshing = null;
              }
            });

          datasetCache.refreshing = refresh;
        }
        return dataset;
      }
    }

    if (!datasetCache.promise) {
      datasetCache.promise = wrapDatasetPromise(fetchFreshDataset());
    }

    return datasetCache.promise;
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

  const SCORE_BAND_META = [
    { key: 'critical', label: 'High', hint: 'score 80–100' },
    { key: 'high', label: 'Elevated', hint: 'score 60–79' },
    { key: 'medium', label: 'Moderate', hint: 'score 40–59' },
    { key: 'low', label: 'Aging', hint: 'score < 40' },
  ];

  const renderScoreDistribution = (stats) => {
    const root = qs('[data-score-distribution]');
    if (!root) return;

    const bands = stats.scoreBands;
    const total = bands
      ? SCORE_BAND_META.reduce((sum, b) => sum + (bands[b.key] || 0), 0)
      : 0;

    if (!bands || total === 0) {
      root.hidden = true;
      return;
    }
    root.hidden = false;

    const bar = qs('[data-score-bar]', root);
    const legend = qs('[data-score-legend]', root);
    if (bar) bar.innerHTML = '';
    if (legend) legend.innerHTML = '';

    if (bar) {
      bar.setAttribute(
        'aria-label',
        SCORE_BAND_META.map((meta) => {
          const count = bands[meta.key] || 0;
          const percent = total ? ((count / total) * 100).toFixed(1) : '0.0';
          return `${meta.label}: ${formatNumber(count)} (${percent}%)`;
        }).join('; ')
      );
    }

    SCORE_BAND_META.forEach((meta) => {
      const count = bands[meta.key] || 0;
      if (!count) return;
      const pct = (count / total) * 100;

      if (bar) {
        const seg = document.createElement('span');
        seg.className = `score-seg score-seg-${meta.key}`;
        seg.style.width = `${pct}%`;
        seg.title = `${meta.label}: ${formatNumber(count)} (${pct.toFixed(1)}%)`;
        bar.appendChild(seg);
      }

      if (legend) {
        const item = document.createElement('span');
        item.className = 'score-legend-item';
        const swatch = document.createElement('span');
        swatch.className = `score-swatch score-seg-${meta.key}`;
        const text = document.createElement('span');
        text.textContent = `${meta.label} ${formatNumber(count)}`;
        item.append(swatch, text);
        item.title = meta.hint;
        legend.appendChild(item);
      }
    });
  };

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

    // Differentiator metrics: block-ready + cross-source-confirmed volume.
    setStatText('high-confidence', formatNumber(stats.highConfidence ?? 0));
    setStatText('corroborated', formatNumber(stats.corroborated ?? 0));
    setStatText('avg-score', stats.avgScore != null ? String(stats.avgScore) : '—');
    const hcPct =
      stats.total > 0 ? ((stats.highConfidence ?? 0) / stats.total) * 100 : 0;
    setStatText('high-confidence-caption', `${hcPct.toFixed(1)}% of the feed`);
    const corrPct =
      stats.total > 0 ? ((stats.corroborated ?? 0) / stats.total) * 100 : 0;
    setStatText('corroborated-caption', `${corrPct.toFixed(1)}% multi-source`);

    renderScoreDistribution(stats);

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

    const sourceRows = stats.sourcesTable || dataset?.sourcesTable || [];
    const typeRows = stats.typesTable || dataset?.typesTable || [];
    const tagRows = stats.tagsTable || dataset?.tagsTable || [];

    if (sourceRows.length) {
      populateTable('sources', sourceRows, 'No active sources in this run.');
      clampTableRows('sources');
    }

    if (typeRows.length) {
      populateTable(
        'types',
        typeRows,
        'No indicator types could be derived.'
      );
      clampTableRows('types');
    }

    if (tagRows.length) {
      populateTable('tags', tagRows, 'No tags were present across indicators.');
      clampTableRows('tags');
    }

    ['sources', 'types', 'tags'].forEach(clampTableRows);
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
    const sourcesEl = qs('[data-site-sources]', root);

    const updateFromStats = (stats, dataset) => {
      if (!stats || !dataset) return;

      const diag = dataset.diag || {};
      const sourceCounts = diag.counts && typeof diag.counts === 'object'
        ? Object.entries(diag.counts)
        : [];
      const healthySources = sourceCounts.length
        ? sourceCounts.filter(([, count]) => count > 0).length
        : stats.activeSources || 0;
      const totalSources = sourceCounts.length || stats.activeSources || 0;
      const failureRows = Array.isArray(diag.failures) ? diag.failures : [];
      const emptySourceNames = Array.isArray(diag.empty_sources)
        ? diag.empty_sources
        : [];
      const issueSources = new Set(
        emptySourceNames.map(normaliseLower).filter(Boolean)
      );
      failureRows.forEach((failure) => {
        const source = normaliseLower(failure?.source ?? failure?.name);
        if (source) issueSources.add(source);
      });
      const issueCount = issueSources.size || failureRows.length;
      const runTime = parseTimestamp(diag.ts)?.time ?? null;
      const hasDiagnostics = runTime != null;
      const ageHours = runTime ? Math.max(0, Date.now() / 1000 - runTime) / 3600 : null;
      const stale = dataset.origin === 'cache-stale' || (ageHours != null && ageHours > 12);
      const degraded = issueCount > 0 || !hasDiagnostics;
      const state = stale ? 'cache-stale' : degraded ? 'degraded' : 'live';
      root.dataset.state = state;

      const originLabel = stale
        ? 'Feed is stale — cached data shown'
        : !hasDiagnostics
        ? 'Feed loaded — freshness unverified'
        : degraded
        ? 'Feed available with source issues'
        : isCacheOrigin(dataset.origin)
        ? 'Feed healthy — cached data shown'
        : 'Feed healthy — live from collector';

      if (labelEl) {
        labelEl.textContent = originLabel;
      }

      const generatedLabel = runTime
        ? formatTimestampForDisplay(runTime)
        : '—';
      const updatedLabel = formatDateTimeLabel(
        stats.newestLastSeen || stats.newestFirstSeen
      );

      const timestampFallback = formatTimestampForDisplay(
        (dataset.fetchedAt != null ? dataset.fetchedAt : Date.now()) / 1000
      );

      if (generatedEl) {
        generatedEl.textContent = generatedLabel !== '—'
          ? generatedLabel
          : 'Not reported';
      }

      if (updatedEl) {
        updatedEl.textContent = updatedLabel !== '—'
          ? updatedLabel
          : timestampFallback;
      }

      if (windowEl) {
        windowEl.textContent = stats.collectionWindow ?? '—';
      }

      if (sourcesEl) {
        sourcesEl.textContent = totalSources
          ? healthySources + ' of ' + totalSources + ' reporting' +
            (issueCount ? ' · ' + issueCount + ' issue' + (issueCount === 1 ? '' : 's') : '')
          : formatNumber(stats.activeSources || 0) + ' active';
      }
    };

    subscribeToDataset((dataset) => {
      if (!dataset || !dataset.stats) return;
      updateFromStats(dataset.stats, dataset);
    });

    loadDataset({})
      .then(({ dataset }) => updateFromStats(dataset.stats, dataset))
      .catch(() => {
        root.dataset.state = 'error';
        if (labelEl) labelEl.textContent = 'Feed unavailable';
        if (sourcesEl) sourcesEl.textContent = 'Unable to verify';
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
    const viewState = qs('[data-preview-state]', container);
    const viewMessage = qs('[data-preview-state-message]', container);
    const viewActions = qs('[data-preview-state-actions]', container);
    const retryButton = qs('[data-preview-retry]', container);
    const facetMenus = qsa('[data-facet-menu]', container);
    const facetRoots = Object.fromEntries(
      qsa('[data-facet-options]', container).map((root) => [
        root.dataset.facetOptions,
        root,
      ])
    );
    const facetSummaries = Object.fromEntries(
      qsa('[data-facet-summary]', container).map((root) => [
        root.dataset.facetSummary,
        root,
      ])
    );
    const signalSelect = qs('[data-preview-highlight]', container);
    const limitSelect = qs('[data-preview-limit]', container);
    const sortSelect = qs('[data-preview-sort-select]', container);
    const searchInput = qs('[data-preview-search]', container);
    const clearButton = qs('[data-preview-clear]', container);
    const shareButton = qs('[data-preview-share]', container);
    const filterCount = qs('[data-preview-filter-count]', container);
    const refreshButton = qs('[data-preview-refresh]');
    const sortButtons = qsa('[data-preview-sort]', table);

    const summary = {
      root: qs('[data-preview-summary]', container),
      visible: qs('[data-preview-visible]', container),
      total: qs('[data-preview-total]', container),
      high: qs('[data-preview-high]', container),
      highPct: qs('[data-preview-high-percent]', container),
      corroborated: qs('[data-preview-corroborated]', container),
      topTag: qs('[data-preview-top-tag]', container),
      topTagCount: qs('[data-preview-top-tag-count]', container),
      pool: qs('[data-preview-pool]', container),
      meta: qs('[data-preview-meta]', container),
      origin: qs('[data-preview-origin]', container),
      refreshed: qs('[data-preview-refreshed]', container),
      relative: qs('[data-preview-relative]', container),
    };

    const state = {
      rows: [],
      types: [],
      sources: [],
      tags: [],
      scoreBands: [],
      ageBands: [],
      type: 'all',
      source: 'all',
      tag: 'all',
      signal: 'all',
      minScore: 0,
      age: 'all',
      search: '',
      limit: DEFAULT_PREVIEW_LIMIT,
      sort: 'score',
      direction: 'desc',
      expanded: new Set(),
      origin: 'network',
      fetchedAt: null,
      stats: null,
      sourcePool: 0,
      loading: false,
    };

    const urlKeys = ['type', 'source', 'tag', 'signal', 'score', 'age', 'rows', 'sort', 'dir'];
    const readUrl = () => {
      if (dashboardCore) {
        Object.assign(
          state,
          dashboardCore.readViewState(
            window.location.search,
            window.location.hash
          )
        );
        return;
      }
      const params = new URLSearchParams(window.location.search);
      state.type = params.get('type') || 'all';
      state.source = params.get('source') || 'all';
      state.tag = params.get('tag') || 'all';
      state.signal = params.get('signal') || 'all';
      state.minScore = Number(params.get('score')) || 0;
      state.age = params.get('age') || 'all';
      const limit = Number(params.get('rows'));
      if ([12, 25, 50, 100].includes(limit)) state.limit = limit;
      const sort = params.get('sort');
      if (['indicator', 'type', 'score', 'sources', 'lastSeen'].includes(sort)) {
        state.sort = sort;
      }
      state.direction = params.get('dir') === 'asc' ? 'asc' : 'desc';
      if (window.location.hash.startsWith('#view=')) {
        try {
          const shared = JSON.parse(decodeURIComponent(window.location.hash.slice(6)));
          if (typeof shared?.q === 'string') state.search = shared.q;
        } catch (error) {
          console.warn('Invalid shared dashboard view ignored', error);
        }
      }
    };

    const writeUrl = ({ includeSearch = false } = {}) => {
      if (dashboardCore) {
        const url = dashboardCore.writeViewUrl(
          window.location.href,
          state,
          includeSearch
        );
        window.history.replaceState(null, '', url);
        return url;
      }
      const url = new URL(window.location.href);
      urlKeys.forEach((key) => url.searchParams.delete(key));
      if (state.type !== 'all') url.searchParams.set('type', state.type);
      if (state.source !== 'all') url.searchParams.set('source', state.source);
      if (state.tag !== 'all') url.searchParams.set('tag', state.tag);
      if (state.signal !== 'all') url.searchParams.set('signal', state.signal);
      if (state.minScore) url.searchParams.set('score', String(state.minScore));
      if (state.age !== 'all') url.searchParams.set('age', state.age);
      if (state.limit !== DEFAULT_PREVIEW_LIMIT) {
        url.searchParams.set('rows', String(state.limit));
      }
      if (state.sort !== 'score') url.searchParams.set('sort', state.sort);
      if (state.direction !== 'desc') url.searchParams.set('dir', state.direction);
      if (includeSearch && state.search) {
        url.hash = 'view=' + encodeURIComponent(JSON.stringify({ q: state.search }));
      } else if (url.hash.startsWith('#view=')) {
        url.hash = '';
      }
      window.history.replaceState(null, '', url);
      return url;
    };

    readUrl();

    const setStatus = (message, mode = 'idle') => {
      if (!statusEl) return;
      statusEl.textContent = message;
      statusEl.dataset.status = mode;
    };

    const setView = (mode, message = '') => {
      if (!viewState) return;
      viewState.hidden = mode === 'ready';
      viewState.dataset.state = mode;
      if (viewMessage) viewMessage.textContent = message;
      if (viewActions) viewActions.hidden = mode !== 'error';
    };

    const effectiveScore = (row) => {
      if (dashboardCore) return dashboardCore.effectiveScore(row);
      if (typeof row?.score === 'number') return row.score;
      return [0, 40, 60, 80][confidenceRankForRow(row)] || 0;
    };

    const rowKey = (row) =>
      normaliseLower(row.type) + '\u0000' + normaliseLower(row.indicator);

    const sourceCount = (rows) => {
      const sources = new Set();
      rows.forEach((row) => {
        const values = row.sourceList?.length ? row.sourceList : [row.source];
        values.forEach((source) => {
          const key = normaliseLower(source);
          if (key) sources.add(key);
        });
      });
      return sources.size;
    };

    const updateMeta = () => {
      if (!summary.meta) return;
      summary.meta.hidden = !state.rows.length;
      if (!state.rows.length) return;
      if (summary.pool) summary.pool.textContent = formatNumber(state.sourcePool);
      if (summary.origin) {
        summary.origin.textContent =
          state.origin === 'cache'
            ? 'Cache (fresh)'
            : state.origin === 'cache-stale'
            ? 'Cache (stale)'
            : 'Network';
      }
      if (summary.refreshed && state.fetchedAt) {
        summary.refreshed.textContent = formatTimestampForDisplay(state.fetchedAt / 1000);
      }
      if (summary.relative && state.fetchedAt) {
        const relative = formatRelativeTimeFromNow(state.fetchedAt / 1000);
        summary.relative.textContent = relative ? ' (' + relative + ')' : '';
      }
      const earliest = state.stats?.earliestFirstSeen;
      const newest = state.stats?.newestFirstSeen;
      setText(qs('[data-preview-oldest]', container), earliest?.date ?? '—');
      setText(qs('[data-preview-newest]', container), newest?.date ?? '—');
      setText(qs('[data-preview-oldest-relative]', container), earliest?.relative ?? '—');
      setText(qs('[data-preview-newest-relative]', container), newest?.relative ?? '—');
    };

    const updateSummary = (matches, displayed) => {
      if (!summary.root) return;
      summary.root.hidden = !matches.length;
      if (!matches.length) return;
      const high = matches.filter((row) => effectiveScore(row) >= 80).length;
      const corroborated = matches.filter((row) => row.sourceCount >= 2).length;
      setText(summary.visible, formatNumber(displayed.length));
      setText(summary.total, formatNumber(matches.length));
      setText(summary.high, formatNumber(high));
      setText(summary.highPct, ((high / matches.length) * 100).toFixed(1) + '%');
      setText(summary.corroborated, formatNumber(corroborated));

      const tags = new Map();
      matches.forEach((row) => {
        (row.tags || []).forEach((tag) => {
          const key = normaliseLower(tag);
          const entry = tags.get(key) || { label: tag, count: 0 };
          entry.count += 1;
          tags.set(key, entry);
        });
      });
      const top = Array.from(tags.values()).sort(
        (a, b) => b.count - a.count || a.label.localeCompare(b.label)
      )[0];
      setText(summary.topTag, top?.label || 'No tags');
      setText(summary.topTagCount, top ? formatNumber(top.count) + ' matches' : '—');
    };

    const detailField = (label, value) => {
      const dl = document.createElement('dl');
      const dt = document.createElement('dt');
      const dd = document.createElement('dd');
      dt.textContent = label;
      dd.textContent = normaliseString(value) || '—';
      dl.append(dt, dd);
      return dl;
    };

    let rowId = 0;
    const createRow = (row) => {
      rowId += 1;
      const key = rowKey(row);
      const detailsId = 'preview-row-details-' + rowId;
      const expanded = state.expanded.has(key);
      const tr = document.createElement('tr');

      const indicatorCell = document.createElement('td');
      indicatorCell.dataset.title = 'Indicator';
      const indicatorMain = document.createElement('div');
      indicatorMain.className = 'preview-indicator-main';
      const code = document.createElement('code');
      code.textContent = row.indicator || '—';
      indicatorMain.appendChild(code);
      if (row.tags?.length) {
        const tags = document.createElement('div');
        tags.className = 'preview-indicator-tags';
        row.tags.slice(0, 3).forEach((tag) => {
          const pill = document.createElement('span');
          pill.textContent = tag;
          tags.appendChild(pill);
        });
        indicatorMain.appendChild(tags);
      }
      indicatorCell.appendChild(indicatorMain);
      tr.appendChild(indicatorCell);

      const typeCell = document.createElement('td');
      typeCell.dataset.title = 'Type';
      typeCell.textContent = row.type || 'unknown';
      tr.appendChild(typeCell);

      const scoreCell = document.createElement('td');
      scoreCell.dataset.title = 'Score';
      scoreCell.className = confidenceClassFor(row.score ?? row.confidence) || 'confidence-low';
      const scoreDisplay = document.createElement('span');
      scoreDisplay.className = 'score-display';
      scoreDisplay.title = explainScore(row);
      const number = document.createElement('span');
      number.className = 'score-number';
      number.textContent =
        typeof row.score === 'number' ? String(row.score) : normaliseString(row.confidence) || '—';
      const band = document.createElement('span');
      band.className = 'score-band';
      band.textContent = scoreBandLabel(row);
      scoreDisplay.append(number, band);
      scoreCell.appendChild(scoreDisplay);
      tr.appendChild(scoreCell);

      const sourcesCell = document.createElement('td');
      sourcesCell.dataset.title = 'Sources';
      sourcesCell.textContent = primarySourceLabel(row);
      tr.appendChild(sourcesCell);

      const seenCell = document.createElement('td');
      seenCell.dataset.title = 'Last seen';
      seenCell.textContent = row.lastSeenDisplay || row.firstSeenDisplay || '—';
      tr.appendChild(seenCell);

      const actionsCell = document.createElement('td');
      actionsCell.dataset.title = 'Actions';
      const actions = document.createElement('div');
      actions.className = 'preview-row-actions';
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'button ghost row-action';
      copy.textContent = 'Copy';
      copy.setAttribute('aria-label', 'Copy indicator ' + (row.indicator || ''));
      copy.addEventListener('click', async () => {
        copy.disabled = true;
        try {
          await copyToClipboard(row.indicator);
          showToast('Indicator copied to clipboard.');
        } catch (error) {
          showToast('Could not copy the indicator.');
        } finally {
          copy.disabled = false;
        }
      });
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'button ghost row-action';
      toggle.textContent = expanded ? 'Hide' : 'Details';
      toggle.setAttribute('aria-expanded', String(expanded));
      toggle.setAttribute('aria-controls', detailsId);
      const download = document.createElement('button');
      download.type = 'button';
      download.className = 'button ghost row-action';
      download.textContent = 'JSON';
      download.setAttribute('aria-label', 'Download ' + row.indicator + ' as JSON');
      download.addEventListener('click', () => {
        downloadJson(row);
        showToast('Indicator JSON downloaded.');
      });
      actions.append(copy, toggle, download);
      actionsCell.appendChild(actions);
      tr.appendChild(actionsCell);

      const detailRow = document.createElement('tr');
      detailRow.className = 'preview-detail-row';
      detailRow.id = detailsId;
      detailRow.hidden = !expanded;
      const detailCell = document.createElement('td');
      detailCell.colSpan = 6;
      const details = document.createElement('div');
      details.className = 'preview-row-detail';
      details.appendChild(
        detailField(
          'All sources',
          row.sourceList?.length ? row.sourceList.join(', ') : row.source
        )
      );
      details.appendChild(detailField('First seen', row.firstSeenDisplay));
      details.appendChild(detailField('Last seen', row.lastSeenDisplay));
      details.appendChild(
        detailField(
          'Tags / context',
          [row.tags?.join(', '), row.context, row.tlp ? 'TLP:' + row.tlp : '']
            .filter(Boolean)
            .join(' · ')
        )
      );
      const rationale = document.createElement('p');
      rationale.className = 'score-explanation';
      rationale.textContent = explainScore(row);
      details.appendChild(rationale);
      if (row.reference) {
        const reference = document.createElement('a');
        reference.className = 'button ghost';
        reference.href = row.reference;
        reference.target = '_blank';
        reference.rel = 'noopener noreferrer';
        reference.textContent = 'View reporting source';
        details.appendChild(reference);
      }
      detailCell.appendChild(details);
      detailRow.appendChild(detailCell);
      toggle.addEventListener('click', () => {
        const open = detailRow.hidden;
        detailRow.hidden = !open;
        toggle.textContent = open ? 'Hide' : 'Details';
        toggle.setAttribute('aria-expanded', String(open));
        if (open) state.expanded.add(key);
        else state.expanded.delete(key);
      });
      return [tr, detailRow];
    };

    const matchesSignal = (row) => {
      if (state.signal === 'all') return true;
      if (state.signal === 'high') return effectiveScore(row) >= 80;
      if (state.signal === 'corroborated') return row.sourceCount >= 2;
      if (state.signal === 'new') {
        const firstSeen = parseTimestamp(row.firstSeen);
        if (!firstSeen) return false;
        const age = Date.now() / 1000 - firstSeen.time;
        return age >= -300 && age <= 48 * 3600;
      }
      return true;
    };

    const filteredRows = () => {
      if (dashboardCore) {
        return state.rows.filter((row) => dashboardCore.matchesRow(row, state));
      }
      const rawQuery = normaliseLower(state.search);
      const refangedQuery = normaliseLower(refang(state.search));
      const maxAge = state.age === 'all' ? null : Number(state.age);
      return state.rows.filter((row) => {
        if (!matchesSignal(row)) return false;
        if (state.type !== 'all' && normaliseLower(row.type) !== state.type) return false;
        if (
          state.source !== 'all' &&
          !(row.sourceList?.length ? row.sourceList : [row.source]).some(
            (source) => normaliseLower(source) === state.source
          )
        ) return false;
        if (state.tag !== 'all' && !(row.tagsLower || []).includes(state.tag)) return false;
        if (effectiveScore(row) < state.minScore) return false;
        if (maxAge != null) {
          if (typeof row.bestTimestamp !== 'number') return false;
          const age = Date.now() / 1000 - row.bestTimestamp;
          if (age < -300 || age > maxAge * 3600) return false;
        }
        if (rawQuery || refangedQuery) {
          const raw = [
            row.indicator,
            row.type,
            ...(row.sourceList || []),
            ...(row.tags || []),
            row.context,
          ].filter(Boolean).join(' ').toLowerCase();
          if (!raw.includes(rawQuery) && !refang(raw).toLowerCase().includes(refangedQuery)) {
            return false;
          }
        }
        return true;
      });
    };

    const compare = (a, b) => {
      if (dashboardCore) return dashboardCore.compareRows(a, b, state);
      let left;
      let right;
      if (state.sort === 'indicator') {
        left = normaliseLower(a.indicator);
        right = normaliseLower(b.indicator);
      } else if (state.sort === 'type') {
        left = normaliseLower(a.type);
        right = normaliseLower(b.type);
      } else if (state.sort === 'sources') {
        left = a.sourceCount || 0;
        right = b.sourceCount || 0;
      } else if (state.sort === 'lastSeen') {
        left = a.bestTimestamp ?? -Infinity;
        right = b.bestTimestamp ?? -Infinity;
      } else {
        left = effectiveScore(a);
        right = effectiveScore(b);
      }
      let result = typeof left === 'string'
        ? left.localeCompare(String(right))
        : left - right;
      if (state.direction === 'desc') result *= -1;
      return result ||
        (b.sourceCount || 0) - (a.sourceCount || 0) ||
        normaliseLower(a.indicator).localeCompare(normaliseLower(b.indicator));
    };

    const updateSort = () => {
      sortButtons.forEach((button) => {
        const active = button.dataset.previewSort === state.sort;
        const th = button.closest('th');
        if (th) {
          th.setAttribute(
            'aria-sort',
            active ? (state.direction === 'asc' ? 'ascending' : 'descending') : 'none'
          );
        }
        const icon = button.querySelector('[aria-hidden="true"]');
        if (icon) icon.textContent = active ? (state.direction === 'asc' ? '↑' : '↓') : '↕';
      });
      if (sortSelect) sortSelect.value = state.sort + ':' + state.direction;
    };

    const render = (rows) => {
      if (!tbody || !table) return;
      tbody.innerHTML = '';
      rowId = 0;
      if (!rows.length) {
        table.hidden = true;
        return;
      }
      const fragment = document.createDocumentFragment();
      rows.forEach((row) => {
        const [main, detail] = createRow(row);
        fragment.append(main, detail);
      });
      tbody.appendChild(fragment);
      table.hidden = false;
    };

    const activeFilterCount = () => [
      ...(state.types || []),
      ...(state.sources || []),
      ...(state.tags || []),
      ...(state.scoreBands || []),
      ...(state.ageBands || []),
      state.signal !== 'all',
      Boolean(state.search.trim()),
    ].filter(Boolean).length;

    const updateActions = () => {
      const count = activeFilterCount();
      if (clearButton) clearButton.disabled = !state.rows.length || !count;
      if (filterCount) {
        filterCount.hidden = !count;
        filterCount.textContent = String(count);
      }
      if (shareButton) shareButton.disabled = !state.rows.length;
    };

    const apply = ({ sync = true } = {}) => {
      const matches = filteredRows().sort(compare);
      const displayed = matches.slice(0, state.limit);
      render(displayed);
      updateSummary(matches, displayed);
      updateMeta();
      updateSort();
      updateActions();
      if (!matches.length) {
        setView('empty', 'No indicators match this view. Clear a filter or broaden the search.');
        setStatus('No indicators match the current filters.', 'empty');
      } else {
        setView('ready');
        const cacheNote = isCacheOrigin(state.origin) ? ' Cached data is shown.' : '';
        setStatus(
          'Showing ' + formatNumber(displayed.length) + ' of ' +
            formatNumber(matches.length) + ' matching indicators.' + cacheNote,
          isCacheOrigin(state.origin) ? 'stale' : 'ready'
        );
      }
      if (sync) writeUrl();
    };

    const facetEmptyLabels = {
      types: 'All types',
      sources: 'All sources',
      tags: 'All tags',
      scoreBands: 'Any score',
      ageBands: 'Any time',
    };

    const updateFacetSummary = (key) => {
      const output = facetSummaries[key];
      if (!output) return;
      const selected = state[key] || [];
      if (!selected.length) {
        output.textContent = facetEmptyLabels[key];
        return;
      }
      if (selected.length === 1) {
        const input = facetRoots[key]?.querySelector(
          `input[value="${CSS.escape(selected[0])}"]`
        );
        output.textContent = input?.closest('label')?.textContent.trim() || selected[0];
        return;
      }
      output.textContent = `${selected.length} selected`;
    };

    const populateFacet = (root, values, key) => {
      if (!root) return;
      const counts = new Map();
      state.rows.forEach((row) => {
        values(row).forEach((entry) => {
          const value = normaliseLower(entry);
          if (!value) return;
          const current = counts.get(value) || { label: entry, count: 0 };
          current.count += 1;
          counts.set(value, current);
        });
      });
      qsa('label', root).forEach((label) => label.remove());
      Array.from(counts.entries())
        .sort((a, b) => b[1].count - a[1].count || a[1].label.localeCompare(b[1].label))
        .forEach(([value, entry]) => {
          const label = document.createElement('label');
          const input = document.createElement('input');
          const text = document.createElement('span');
          input.type = 'checkbox';
          input.value = value;
          input.checked = (state[key] || []).includes(value);
          text.textContent = `${entry.label} (${formatNumber(entry.count)})`;
          label.append(input, text);
          root.appendChild(label);
        });
      const valid = new Set(counts.keys());
      state[key] = (state[key] || []).filter((value) => valid.has(value));
      root.disabled = !state.rows.length || counts.size === 0;
      updateFacetSummary(key);
    };

    const populateFacets = () => {
      populateFacet(facetRoots.types, (row) => [row.type], 'types');
      populateFacet(
        facetRoots.sources,
        (row) => row.sourceList?.length ? row.sourceList : [row.source],
        'sources'
      );
      populateFacet(facetRoots.tags, (row) => row.tags || [], 'tags');
    };

    const syncControls = () => {
      if (!['all', 'high', 'corroborated', 'new'].includes(state.signal)) {
        state.signal = 'all';
      }
      Object.entries(facetRoots).forEach(([key, root]) => {
        qsa('input[type="checkbox"]', root).forEach((input) => {
          input.checked = (state[key] || []).includes(input.value);
        });
        updateFacetSummary(key);
      });
      if (signalSelect) signalSelect.value = state.signal;
      if (limitSelect) limitSelect.value = String(state.limit);
      if (searchInput) searchInput.value = state.search;
      updateSort();
    };

    const setControlsDisabled = (disabled) => {
      Object.values(facetRoots).forEach((root) => {
        root.disabled = disabled;
      });
      [
        signalSelect,
        limitSelect,
        sortSelect,
        searchInput,
        refreshButton,
        clearButton,
        shareButton,
      ].forEach((control) => {
        if (control) control.disabled = disabled;
      });
    };

    const useDataset = (dataset) => {
      state.rows = selectPreviewRows(dataset?.entries || [], PREVIEW_CACHE_LIMIT);
      state.origin = dataset?.origin || 'network';
      state.fetchedAt = typeof dataset?.fetchedAt === 'number' ? dataset.fetchedAt : null;
      state.stats = dataset?.stats || null;
      state.sourcePool = sourceCount(state.rows);
      populateFacets();
      syncControls();
      apply({ sync: false });
      if (dataset?.stats) applyStats(dataset.stats, dataset);
    };

    const load = async ({ forceRefresh = false } = {}) => {
      state.loading = true;
      container.dataset.loading = 'true';
      container.setAttribute('aria-busy', 'true');
      setControlsDisabled(true);
      setView('loading', forceRefresh ? 'Refreshing indicators…' : 'Loading the latest indicators…');
      setStatus(forceRefresh ? 'Refreshing the feed…' : 'Loading the feed…', 'loading');
      try {
        const { dataset } = await loadDataset({
          previewLimit: PREVIEW_CACHE_LIMIT,
          forceRefresh,
        });
        useDataset(dataset);
      } catch (error) {
        console.error('Unable to load live preview', error);
        state.rows = [];
        render([]);
        updateSummary([], []);
        if (summary.meta) summary.meta.hidden = true;
        setView('error', 'The live feed could not be loaded. Retry or use the CSV export.');
        setStatus('Feed unavailable. Export links remain available.', 'error');
      } finally {
        state.loading = false;
        delete container.dataset.loading;
        container.setAttribute('aria-busy', 'false');
        const hasRows = state.rows.length > 0;
        Object.values(facetRoots).forEach((root) => {
          root.disabled = !hasRows;
        });
        [signalSelect, sortSelect, searchInput, shareButton]
          .forEach((control) => {
            if (control) control.disabled = !hasRows;
          });
        if (limitSelect) limitSelect.disabled = false;
        if (refreshButton) refreshButton.disabled = false;
        updateActions();
      }
    };

    const bind = (control, key, transform = (value) => value) => {
      control?.addEventListener('change', () => {
        state[key] = transform(control.value);
        apply();
      });
    };
    bind(signalSelect, 'signal');

    Object.entries(facetRoots).forEach(([key, root]) => {
      root.addEventListener('change', () => {
        state[key] = qsa('input[type="checkbox"]:checked', root).map(
          (input) => input.value
        );
        updateFacetSummary(key);
        apply();
      });
    });

    facetMenus.forEach((menu) => {
      menu.addEventListener('toggle', () => {
        if (!menu.open) return;
        facetMenus.forEach((other) => {
          if (other !== menu) other.open = false;
        });
      });
    });

    document.addEventListener('click', (event) => {
      if (facetMenus.some((menu) => menu.contains(event.target))) return;
      facetMenus.forEach((menu) => {
        menu.open = false;
      });
    });

    limitSelect?.addEventListener('change', () => {
      const limit = Number(limitSelect.value);
      if ([12, 25, 50, 100].includes(limit)) {
        state.limit = limit;
        apply();
      }
    });
    sortSelect?.addEventListener('change', () => {
      const [sort, direction] = sortSelect.value.split(':');
      state.sort = sort;
      state.direction = direction === 'asc' ? 'asc' : 'desc';
      apply();
    });
    sortButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const sort = button.dataset.previewSort;
        if (state.sort === sort) {
          state.direction = state.direction === 'asc' ? 'desc' : 'asc';
        } else {
          state.sort = sort;
          state.direction = ['indicator', 'type'].includes(sort) ? 'asc' : 'desc';
        }
        apply();
      });
    });

    let debounce;
    searchInput?.addEventListener('input', (event) => {
      window.clearTimeout(debounce);
      debounce = window.setTimeout(() => {
        state.search = event.target.value;
        apply();
      }, 180);
    });
    searchInput?.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        state.search = '';
        searchInput.value = '';
        apply();
      }
    });
    clearButton?.addEventListener('click', () => {
      Object.assign(state, {
        types: [],
        sources: [],
        tags: [],
        scoreBands: [],
        ageBands: [],
        type: 'all',
        source: 'all',
        tag: 'all',
        signal: 'all',
        minScore: 0,
        age: 'all',
        search: '',
      });
      state.expanded.clear();
      syncControls();
      apply();
      searchInput?.focus();
    });
    shareButton?.addEventListener('click', async () => {
      const url = writeUrl({ includeSearch: true });
      try {
        await copyToClipboard(url.toString());
        showToast('Shareable dashboard view copied.');
      } catch (error) {
        showToast('Could not copy the dashboard URL.');
      }
    });
    refreshButton?.addEventListener('click', () => load({ forceRefresh: true }));
    retryButton?.addEventListener('click', () => load({ forceRefresh: true }));

    subscribeToDataset((dataset) => {
      if (!state.loading && dataset?.entries?.length) useDataset(dataset);
    });
    window.addEventListener('popstate', () => {
      readUrl();
      populateFacets();
      syncControls();
      apply({ sync: false });
    });

    load();
  };

  /* ==========================================================================
   *  TOP THREATS SHOWCASE
   * ========================================================================= */

  const TOP_THREATS_LIMIT = 6;

  const scoreBandClass = (score) => {
    if (typeof score !== 'number') return 'threat-medium';
    if (score >= 80) return 'threat-critical';
    if (score >= 60) return 'threat-high';
    if (score >= 40) return 'threat-medium';
    return 'threat-low';
  };

  const makeThreatPill = (cls, text) => {
    const span = document.createElement('span');
    span.className = `threat-pill ${cls}`;
    span.textContent = text;
    return span;
  };

  const makeThreatCard = (row) => {
    const card = document.createElement('article');
    card.className = `threat-card ${scoreBandClass(row.score)}`;

    const scoreBox = document.createElement('div');
    scoreBox.className = 'threat-score';
    const num = document.createElement('span');
    num.className = 'threat-score-num';
    num.textContent =
      typeof row.score === 'number'
        ? String(row.score)
        : (row.confidence ? row.confidence[0].toUpperCase() : '—');
    const lbl = document.createElement('span');
    lbl.className = 'threat-score-label';
    lbl.textContent = 'score';
    scoreBox.append(num, lbl);

    const body = document.createElement('div');
    body.className = 'threat-body';

    const ind = document.createElement('div');
    ind.className = 'threat-indicator';
    ind.textContent = row.indicator || '—';
    if (row.indicator) ind.title = row.indicator;
    body.appendChild(ind);

    const pills = document.createElement('div');
    pills.className = 'threat-pills';
    pills.appendChild(makeThreatPill('type', row.type || 'unknown'));
    if ((row.sourceCount || 0) >= 2) {
      const p = makeThreatPill('confirmed', `${row.sourceCount}× confirmed`);
      if (Array.isArray(row.sourceList)) p.title = row.sourceList.join(', ');
      pills.appendChild(p);
    }
    const rel = formatRelativeTimeFromNow(row.bestTimestamp);
    if (rel) pills.appendChild(makeThreatPill('time', rel));
    body.appendChild(pills);

    if (row.tags && row.tags.length) {
      const tags = document.createElement('div');
      tags.className = 'threat-tags';
      row.tags.slice(0, 3).forEach((t) => {
        const s = document.createElement('span');
        s.textContent = t;
        tags.appendChild(s);
      });
      body.appendChild(tags);
    }

    card.append(scoreBox, body);
    return card;
  };

  const initialiseTopThreats = () => {
    const section = qs('[data-top-threats-section]');
    const grid = qs('[data-top-threats]');
    if (!section || !grid) return;

    const render = (dataset) => {
      const entries = (dataset && dataset.entries) || [];
      // Only a scored feed makes a meaningful "top threats" ranking; hide the
      // showcase for legacy pre-scoring data instead of showing blank boxes.
      if (!entries.length || !entries.some((e) => typeof e.score === 'number')) {
        section.hidden = true;
        return;
      }
      const ranked = entries
        .slice()
        .sort((a, b) => {
          const sa = typeof a.score === 'number' ? a.score : -1;
          const sb = typeof b.score === 'number' ? b.score : -1;
          if (sa !== sb) return sb - sa;
          const ca = a.sourceCount || 0;
          const cb = b.sourceCount || 0;
          if (ca !== cb) return cb - ca;
          return (b.bestTimestamp || 0) - (a.bestTimestamp || 0);
        })
        .slice(0, TOP_THREATS_LIMIT);

      grid.innerHTML = '';
      ranked.forEach((row) => grid.appendChild(makeThreatCard(row)));
      section.hidden = false;
    };

    subscribeToDataset((dataset) => {
      if (dataset && !isCacheOrigin(dataset.origin)) render(dataset);
    });
    loadDataset({})
      .then(({ dataset }) => render(dataset))
      .catch((error) => console.warn('Top threats failed to load', error));
  };

  /* ==========================================================================
   *  IOC LOOKUP
   * ========================================================================= */

  // Two-stage search: first check the already-loaded compact dataset
  // (instant), then — only if the user asks and it's not found — stream the
  // full feed looking for an exact match, aborting the reader as soon as it
  // hits. Keeps the common case free and the full download opt-in.
  const initialiseIocLookup = () => {
    const form = qs('[data-lookup-form]');
    if (!form) return;

    const input = qs('[data-lookup-input]', form);
    const button = qs('[data-lookup-submit]', form);
    const resultBox = qs('[data-lookup-result]');
    let lookupRequest = 0;
    let lookupController = null;

    const normaliseQuery = (value) => refang(normaliseString(value)).toLowerCase();

    const renderResult = (state, row, checkedFull) => {
      if (!resultBox) return;
      resultBox.hidden = false;
      resultBox.dataset.state = state;

      if (state === 'found' && row) {
        resultBox.innerHTML = '';
        const scoreClass = confidenceClassFor(row.score ?? row.confidence);
        const head = document.createElement('div');
        head.className = 'lookup-hit-header';
        const badge = document.createElement('span');
        badge.className = 'lookup-hit-badge';
        badge.textContent = 'Found in SwiftIOC';
        const score = document.createElement('span');
        score.className = `lookup-hit-score ${scoreClass || ''}`;
        score.textContent =
          `${typeof row.score === 'number' ? row.score : row.confidence || 'Unscored'} · ${scoreBandLabel(row)}`;
        head.append(badge, score);
        resultBox.appendChild(head);

        const indicator = document.createElement('code');
        indicator.className = 'lookup-indicator';
        indicator.textContent = row.indicator;
        resultBox.appendChild(indicator);

        const details = document.createElement('dl');
        details.className = 'lookup-detail-grid';
        const appendDetail = (label, value) => {
          const wrapper = document.createElement('div');
          const term = document.createElement('dt');
          const description = document.createElement('dd');
          term.textContent = label;
          description.textContent = normaliseString(value) || '—';
          wrapper.append(term, description);
          details.appendChild(wrapper);
        };
        appendDetail('Type', row.type || 'unknown');
        appendDetail(
          'Sources',
          row.sourceList?.length ? row.sourceList.join(', ') : row.source
        );
        appendDetail('First seen', row.firstSeenDisplay);
        appendDetail('Last seen', row.lastSeenDisplay);
        resultBox.appendChild(details);

        const rationale = document.createElement('p');
        rationale.className = 'score-explanation';
        rationale.textContent = explainScore(row);
        resultBox.appendChild(rationale);

        const actions = document.createElement('div');
        actions.className = 'lookup-actions';
        const makeAction = (label, handler) => {
          const action = document.createElement('button');
          action.type = 'button';
          action.className = 'button ghost';
          action.textContent = label;
          action.addEventListener('click', handler);
          return action;
        };
        actions.appendChild(
          makeAction('Copy indicator', async () => {
            try {
              await copyToClipboard(row.indicator);
              showToast('Indicator copied to clipboard.');
            } catch (error) {
              showToast('Could not copy the indicator.');
            }
          })
        );
        actions.appendChild(
          makeAction('Download JSON', () => downloadJson(row))
        );
        actions.appendChild(
          makeAction('Share result', async () => {
            const url = new URL(window.location.href);
            url.hash = `ioc=${encodeURIComponent(row.indicator)}`;
            window.history.replaceState(null, '', url);
            try {
              await copyToClipboard(url.toString());
              showToast('Shareable IOC lookup copied.');
            } catch (error) {
              showToast('Could not copy the lookup URL.');
            }
          })
        );
        if (row.reference) {
          const reference = document.createElement('a');
          reference.className = 'button ghost';
          reference.href = row.reference;
          reference.target = '_blank';
          reference.rel = 'noopener noreferrer';
          reference.textContent = 'View source';
          actions.appendChild(reference);
        }
        resultBox.appendChild(actions);
        return;
      }

      if (state === 'loading') {
        resultBox.textContent = 'Checking the top feed…';
        return;
      }
      if (state === 'loading-full') {
        resultBox.textContent =
          'Not in the top feed — checking the full archive (this downloads the full feed once)…';
        return;
      }
      if (state === 'not-found') {
        resultBox.textContent = checkedFull
          ? 'Not present in the current SwiftIOC feed. This is not a guarantee that the indicator is benign.'
          : 'Not present in the compact dashboard feed.';
        return;
      }
      if (state === 'error') {
        resultBox.textContent =
          'Could not complete the lookup. No clean result has been inferred; please retry.';
      }
    };

    const searchFullFeed = async (needle, signal) => {
      const response = await fetch(INDICATORS_JSONL_URL, {
        headers: { Accept: 'application/jsonl, text/plain' },
        signal,
      });
      if (!response.ok) {
        throw new Error(
          `Full feed request failed: ${response.status} ${response.statusText}`
        );
      }
      if (!response.body || typeof response.body.getReader !== 'function') {
        const text = await response.text();
        for (const line of text.split(/\r?\n/)) {
          const parsed = parseJsonSafely(line);
          const normalised = parsed && normaliseRow(parsed);
          if (normalised && normaliseQuery(normalised.indicator) === needle) return normalised;
        }
        return null;
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let idx;
          while ((idx = buffer.indexOf('\n')) >= 0) {
            const line = buffer.slice(0, idx).trim();
            buffer = buffer.slice(idx + 1);
            if (!line) continue;
            const parsed = parseJsonSafely(line);
            const normalised = parsed && normaliseRow(parsed);
            if (normalised && normaliseQuery(normalised.indicator) === needle) {
              reader.cancel().catch(() => {});
              return normalised;
            }
          }
        }
      } finally {
        try {
          reader.releaseLock();
        } catch (e) {
          // already released via cancel()
        }
      }
      return null;
    };

    const runLookup = async () => {
      const needle = normaliseQuery(input?.value);
      const valid = needle.length >= 3 && needle.length <= 2048;
      if (input) input.setAttribute('aria-invalid', String(!valid));
      if (!valid) {
        if (resultBox) {
          resultBox.hidden = false;
          resultBox.dataset.state = 'error';
          resultBox.textContent =
            'Enter a complete indicator between 3 and 2,048 characters.';
        }
        input?.focus();
        return;
      }

      lookupRequest += 1;
      const currentRequest = lookupRequest;
      lookupController?.abort();
      lookupController = new AbortController();

      if (button) {
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
      }
      renderResult('loading');

      try {
        const { dataset } = await loadDataset({});
        if (currentRequest !== lookupRequest) return;
        const hit = (dataset.entries || []).find(
          (row) => normaliseQuery(row.indicator) === needle
        );
        if (hit) {
          renderResult('found', hit, false);
          return;
        }

        renderResult('loading-full');
        const fullHit = await searchFullFeed(
          needle,
          lookupController.signal
        );
        if (currentRequest !== lookupRequest) return;
        if (fullHit) {
          renderResult('found', fullHit, true);
        } else {
          renderResult('not-found', null, true);
        }
      } catch (error) {
        if (error?.name !== 'AbortError') {
          console.error('IOC lookup failed', error);
          renderResult('error');
        }
      } finally {
        if (button && currentRequest === lookupRequest) {
          button.disabled = false;
          button.removeAttribute('aria-busy');
        }
      }
    };

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      runLookup();
    });

    if (window.location.hash.startsWith('#ioc=')) {
      try {
        input.value = decodeURIComponent(window.location.hash.slice(5));
        runLookup();
      } catch (error) {
        console.warn('Invalid IOC lookup link ignored', error);
      }
    }
  };

  /* ==========================================================================
   *  TREND SPARKLINE
   * ========================================================================= */

  const initialiseTrendSparkline = () => {
    const container = qs('[data-trend-sparkline]');
    if (!container) return;

    fetch(HISTORY_URL, { headers: { Accept: 'application/json' } })
      .then((r) => (r.ok ? r.json() : null))
      .then((history) => {
        if (!Array.isArray(history) || history.length < 2) {
          container.hidden = true;
          return;
        }

        const totals = history.map((h) => (typeof h.total === 'number' ? h.total : 0));
        const min = Math.min(...totals);
        const max = Math.max(...totals);
        const range = max - min || 1;
        const w = 280;
        const h = 48;
        const pad = 3;

        const points = totals.map((value, i) => {
          const x = totals.length > 1 ? (i / (totals.length - 1)) * (w - pad * 2) + pad : pad;
          const y = h - pad - ((value - min) / range) * (h - pad * 2);
          return `${x.toFixed(1)},${y.toFixed(1)}`;
        });

        const latest = history[history.length - 1];
        const first = history[0];
        const delta = (latest.total || 0) - (first.total || 0);
        const trendLabel =
          delta > 0 ? `▲ +${formatNumber(delta)}` : delta < 0 ? `▼ ${formatNumber(delta)}` : '— flat';

        container.innerHTML = '';
        container.hidden = false;

        const svgNs = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNs, 'svg');
        svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
        svg.setAttribute('class', 'trend-svg');
        svg.setAttribute('aria-hidden', 'true');

        const polyline = document.createElementNS(svgNs, 'polyline');
        polyline.setAttribute('points', points.join(' '));
        polyline.setAttribute('class', 'trend-line');
        svg.appendChild(polyline);

        if (points.length) {
          const [lastX, lastY] = points[points.length - 1].split(',');
          const dot = document.createElementNS(svgNs, 'circle');
          dot.setAttribute('cx', lastX);
          dot.setAttribute('cy', lastY);
          dot.setAttribute('r', '2.5');
          dot.setAttribute('class', 'trend-dot');
          svg.appendChild(dot);
        }

        const label = document.createElement('span');
        label.className = 'trend-label';
        label.textContent = `${trendLabel} over ${history.length} runs`;
        container.setAttribute(
          'aria-label',
          `Indicator count: ${formatNumber(latest.total || 0)}; ${trendLabel} over ${history.length} runs`
        );

        container.appendChild(svg);
        container.appendChild(label);
      })
      .catch((error) => {
        console.warn('Trend sparkline unavailable', error);
        container.hidden = true;
      });
  };

  const initialiseDownloadFallbacks = () => {
    const availability = new Map();
    qsa('[data-download-fallback]').forEach((link) => {
      const primaryUrl = link.href;
      if (!availability.has(primaryUrl)) {
        availability.set(
          primaryUrl,
          fetch(primaryUrl, { method: 'HEAD', cache: 'no-store' })
            .then((response) => response.ok)
            .catch(() => false)
        );
      }

      availability.get(primaryUrl).then((available) => {
        if (available) return;
        link.href = resolveIocUrl(link.dataset.downloadFallback);
        link.title =
          'The curated export is not available in this snapshot; downloading the complete feed instead.';
        const title = link.querySelector('span');
        const caption = link.querySelector('small');
        if (title) {
          title.textContent = link.dataset.fallbackTitle || 'Download complete feed';
          if (caption) {
            caption.textContent = link.dataset.fallbackCaption || 'Current snapshot';
          }
        } else if (link.dataset.fallbackLabel) {
          link.textContent = link.dataset.fallbackLabel;
        }
      });
    });
  };

  /* ==========================================================================
   *  BOOTSTRAP
   * ========================================================================= */

  initialiseTableToggles();
  initialiseStatusBanner();
  initialiseTopThreats();
  initialiseIocLookup();
  initialiseTrendSparkline();
  initialiseDownloadFallbacks();
  loadStats();
  initialisePreview();
})();
