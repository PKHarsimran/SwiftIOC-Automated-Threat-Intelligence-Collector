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
    const text = stringValue(value);
    if (!text) return null;
    // Match dashboard parseTimestamp for Unix seconds/milliseconds supplied
    // as either numbers or strings; do not substitute firstSeen timestamps.
    const numeric = Number(text);
    if (Number.isFinite(numeric)) {
      const time = numeric > 1e12 && numeric < 1e13 ? Math.round(numeric / 1000) : numeric;
      return Number.isNaN(new Date(time * 1000).getTime()) ? null : time;
    }
    const parsed = Date.parse(text);
    return Number.isNaN(parsed) ? null : parsed / 1000;
  };

  const rowSources = (row) =>
    row?.sourceList?.length ? row.sourceList : [row?.source || 'unknown'];

  const selectedValues = (many, one) => {
    if (Array.isArray(many)) return many.filter(Boolean);
    return one && one !== 'all' ? [one] : [];
  };

  // CSV cells beginning with spreadsheet formula prefixes can execute when a
  // downloaded investigation file is opened. Prefix them with an apostrophe so
  // an IOC remains data in Excel, LibreOffice, and similar tools.
  const csvCell = (value) => {
    let text = stringValue(value);
    if (/^[=+\-@]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  };

  const rowsToCsv = (rows) => {
    const columns = [
      ['indicator', 'Indicator'],
      ['type', 'Type'],
      ['score', 'Score'],
      ['confidence', 'Confidence'],
      ['source', 'Sources'],
      ['firstSeen', 'First seen'],
      ['lastSeen', 'Last seen'],
      ['tags', 'Tags'],
      ['reference', 'Reference'],
      ['context', 'Context'],
    ];
    const values = Array.isArray(rows) ? rows : [];
    return [
      columns.map(([, label]) => csvCell(label)).join(','),
      ...values.map((row) => columns.map(([key]) => {
        const value = key === 'tags' && Array.isArray(row?.tags)
          ? row.tags.join(', ')
          : key === 'source' && Array.isArray(row?.sourceList)
          ? row.sourceList.join(', ')
          : row?.[key];
        return csvCell(value);
      }).join(',')),
    ].join('\r\n') + '\r\n';
  };

  const investigationKey = (row) => {
    const type = lower(row?.type) || 'unknown';
    const rawIndicator = stringValue(row?.indicator);
    if (!rawIndicator) return '';
    // URL paths and query components can be case-sensitive. Preserve the full
    // value for URLs while continuing to collapse harmless case differences
    // for domains, IPs, hashes, and the other indicator families.
    const indicator = type === 'url' ? rawIndicator : rawIndicator.toLowerCase();
    return `${type}\u0000${indicator}`;
  };

  // Treat browser storage as untrusted input. Keep only the fields needed by
  // the analyst workspace, cap collection size, and discard duplicate or
  // malformed records before anything is rendered or exported.
  const normaliseInvestigationRows = (value, limit = 50) => {
    if (!Array.isArray(value)) return [];
    const rows = [];
    const seen = new Set();
    const cap = Math.max(1, Math.min(Number(limit) || 50, 250));
    for (const candidate of value) {
      if (!candidate || typeof candidate !== 'object') continue;
      const indicator = stringValue(candidate.indicator);
      if (!indicator || indicator.length > 2048) continue;
      const row = {
        indicator,
        type: stringValue(candidate.type) || 'unknown',
        confidence: stringValue(candidate.confidence),
        source: stringValue(candidate.source),
        sourceList: Array.isArray(candidate.sourceList)
          ? candidate.sourceList.map(stringValue).filter(Boolean).slice(0, 25)
          : [],
        firstSeen: stringValue(candidate.firstSeen),
        lastSeen: stringValue(candidate.lastSeen),
        tags: Array.isArray(candidate.tags)
          ? candidate.tags.map(stringValue).filter(Boolean).slice(0, 50)
          : [],
        reference: stringValue(candidate.reference),
        context: stringValue(candidate.context),
        tlp: stringValue(candidate.tlp),
      };
      if (typeof candidate.score === 'number' && Number.isFinite(candidate.score)) {
        row.score = Math.max(0, Math.min(100, candidate.score));
      }
      const key = investigationKey(row);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      rows.push(row);
      if (rows.length >= cap) break;
    }
    return rows;
  };

  const validIpv4 = (value) => {
    const parts = value.split('.');
    return parts.length === 4 && parts.every((part) =>
      /^\d{1,3}$/.test(part) && Number(part) <= 255
    );
  };

  const validIpv6 = (value) => {
    if (!value.includes(':') || !/^[0-9a-f:.]+$/i.test(value)) return false;
    try {
      return new URL(`http://[${value}]/`).hostname.length > 2;
    } catch (error) {
      return false;
    }
  };

  const validDomain = (value) => value.length <= 253 && value.includes('.') &&
    value.split('.').every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
    );

  const detectionRows = (value) => {
    const rows = [];
    const seen = new Set();
    for (const row of normaliseInvestigationRows(value, 250)) {
      const type = lower(row.type);
      const indicator = refang(row.indicator).replace(/\.$/, '');
      let valid = false;
      if (type === 'ipv4') valid = validIpv4(indicator);
      if (type === 'ipv4_cidr') {
        const [address, prefix, ...rest] = indicator.split('/');
        valid = !rest.length && validIpv4(address) && /^\d{1,2}$/.test(prefix) && Number(prefix) <= 32;
      }
      if (type === 'ipv6') valid = validIpv6(indicator);
      if (type === 'ipv6_cidr') {
        const [address, prefix, ...rest] = indicator.split('/');
        valid = !rest.length && validIpv6(address) &&
          /^\d{1,3}$/.test(prefix) && Number(prefix) <= 128;
      }
      if (type === 'domain') {
        valid = validDomain(indicator);
      }
      const key = `${type}\u0000${indicator.toLowerCase()}`;
      if (!valid || seen.has(key)) continue;
      seen.add(key);
      rows.push({ ...row, type, indicator });
    }
    return rows.sort((a, b) =>
      a.type.localeCompare(b.type) || a.indicator.localeCompare(b.indicator)
    );
  };

  const yamlList = (values, indent) => values
    .map((value) => `${' '.repeat(indent)}- ${JSON.stringify(value)}`)
    .join('\n');

  const rowsToSigma = (value) => {
    const rows = detectionRows(value);
    const addresses = rows.filter((row) => /^ipv[46]$/.test(row.type)).map((row) => row.indicator);
    const networks = rows.filter((row) => /^ipv[46]_cidr$/.test(row.type)).map((row) => row.indicator);
    const domains = rows.filter((row) => row.type === 'domain').map((row) => row.indicator.toLowerCase());
    const documents = [];
    if (addresses.length || networks.length) {
      const networkRule = [
        'title: SwiftIOC investigation network indicators',
        'status: experimental',
        'description: Detects network traffic matching indicators selected in the SwiftIOC analyst workspace.',
        'author: SwiftIOC analyst workspace',
        'tags:',
        '  - attack.command_and_control',
        'logsource:',
        '  category: network_connection',
        'detection:',
      ];
      if (addresses.length) networkRule.push(
        '  ip_source:', '    SourceIp:', yamlList(addresses, 6),
        '  ip_destination:', '    DestinationIp:', yamlList(addresses, 6)
      );
      if (networks.length) networkRule.push(
        '  ip_source_network:', '    SourceIp|cidr:', yamlList(networks, 6),
        '  ip_destination_network:', '    DestinationIp|cidr:', yamlList(networks, 6)
      );
      networkRule.push(
        '  condition: 1 of ip_*',
        'falsepositives:',
        '  - Legitimate shared infrastructure; validate with local context.',
        'level: high',
      );
      documents.push(networkRule.join('\n'));
    }
    if (domains.length) {
      documents.push([
        'title: SwiftIOC investigation DNS indicators',
        'status: experimental',
        'description: Detects DNS queries matching domains selected in the SwiftIOC analyst workspace.',
        'author: SwiftIOC analyst workspace',
        'tags:',
        '  - attack.command_and_control',
        'logsource:',
        '  category: dns',
        'detection:',
        '  domain_exact:',
        '    query:',
        yamlList(domains, 6),
        '  domain_subdomain:',
        '    query|endswith:',
        yamlList(domains.map((domain) => `.${domain}`), 6),
        '  condition: domain_exact or domain_subdomain',
        'falsepositives:',
        '  - Legitimate shared infrastructure; validate with local context.',
        'level: high',
      ].join('\n'));
    }
    return documents.join('\n---\n') + (documents.length ? '\n' : '');
  };

  const stableSid = (text, used) => {
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 16777619) >>> 0;
    }
    let sid = 4000000 + (hash % 900000);
    while (used.has(sid)) sid = 4000000 + ((sid - 3999999) % 900000);
    used.add(sid);
    return sid;
  };

  const rowsToSuricata = (value) => {
    const rules = [
      '# SwiftIOC analyst-workspace detection pack',
      '# Review and tune against local allowlists before enabling enforcement.',
    ];
    const used = new Set();
    for (const row of detectionRows(value)) {
      if (row.type.startsWith('ipv')) {
        const target = row.indicator.includes(':') ? `[${row.indicator}]` : row.indicator;
        for (const [direction, header] of [
          ['inbound', `alert ip ${target} any -> $HOME_NET any`],
          ['outbound', `alert ip $HOME_NET any -> ${target} any`],
        ]) {
          rules.push(`${header} (msg:"SwiftIOC ${direction} investigation match"; ` +
            `classtype:trojan-activity; sid:${stableSid(`ip:${row.indicator}:${direction}`, used)}; rev:1;)`);
        }
      }
      if (row.type === 'domain') {
        rules.push('alert dns $HOME_NET any -> any 53 ' +
          `(msg:"SwiftIOC investigation DNS match"; dns.query; dotprefix; content:".${row.indicator}"; ` +
          `nocase; endswith; classtype:trojan-activity; sid:${stableSid(`dns:${row.indicator}`, used)}; rev:1;)`);
      }
    }
    return rules.join('\n') + '\n';
  };

  const buildCampaignGraph = (value, options = {}) => {
    const rows = Array.isArray(value) ? value.filter((row) => row?.indicator && lower(row.type) !== 'cve') : [];
    const mode = ['all', 'tags', 'sources'].includes(options.mode) ? options.mode : 'all';
    const maxPivots = Math.max(1, Math.min(Number(options.maxPivots) || 6, 10));
    const maxIndicators = Math.max(2, Math.min(Number(options.maxIndicators) || 24, 50));
    const ignoredTags = new Set([
      'aggregated', 'blocklist', 'critical', 'high', 'info', 'ioc', 'low',
      'malicious', 'malware', 'medium', 'threat-intel', 'threat intelligence',
    ]);
    const ignoredSources = new Set(['', 'n/a', 'none', 'unknown', 'unspecified']);
    const sourceNames = new Set(rows.flatMap((row) => rowSources(row).map(lower)));
    const pivots = new Map();

    const addPivot = (kind, label, row) => {
      const clean = stringValue(label).slice(0, 80);
      if (!clean) return;
      const key = `${kind}:${clean.toLowerCase()}`;
      const pivot = pivots.get(key) || { key, kind, label: clean, rows: new Map(), score: 0 };
      const rowKey = investigationKey(row);
      if (!rowKey || pivot.rows.has(rowKey)) return;
      pivot.rows.set(rowKey, row);
      pivot.score += effectiveScore(row) + Math.min(Number(row.sourceCount) || rowSources(row).length, 5) * 5;
      pivots.set(key, pivot);
    };

    rows.forEach((row) => {
      if (mode !== 'sources') {
        const tags = Array.isArray(row.tags) ? row.tags : [];
        tags.slice(0, 25).forEach((tag) => {
          if (!ignoredTags.has(lower(tag)) && !sourceNames.has(lower(tag))) {
            addPivot('tag', tag, row);
          }
        });
      }
      if (mode !== 'tags') {
        rowSources(row).slice(0, 25).forEach((source) => {
          if (!ignoredSources.has(lower(source))) addPivot('source', source, row);
        });
      }
    });

    const selectedPivots = Array.from(pivots.values())
      .filter((pivot) => pivot.rows.size >= 2)
      .sort((a, b) =>
        (b.rows.size * 100 + b.score / b.rows.size) -
          (a.rows.size * 100 + a.score / a.rows.size) ||
        a.key.localeCompare(b.key)
      )
      .slice(0, maxPivots);

    const candidateRows = new Map();
    selectedPivots.forEach((pivot) => {
      Array.from(pivot.rows.values())
        .sort((a, b) =>
          effectiveScore(b) - effectiveScore(a) ||
          (Number(b.sourceCount) || rowSources(b).length) -
            (Number(a.sourceCount) || rowSources(a).length) ||
          stringValue(a.indicator).localeCompare(stringValue(b.indicator))
        )
        .slice(0, 12)
        .forEach((row) => candidateRows.set(investigationKey(row), row));
    });
    const selectedRows = Array.from(candidateRows.values())
      .sort((a, b) =>
        effectiveScore(b) - effectiveScore(a) ||
        stringValue(a.indicator).localeCompare(stringValue(b.indicator))
      )
      .slice(0, maxIndicators);
    const selectedKeys = new Set(selectedRows.map(investigationKey));
    const renderedPivots = selectedPivots.filter((pivot) =>
      Array.from(pivot.rows.keys()).some((key) => selectedKeys.has(key))
    );

    const nodes = [
      ...renderedPivots.map((pivot) => ({
        id: `pivot:${pivot.key}`,
        kind: 'pivot',
        pivotKind: pivot.kind,
        label: pivot.label,
        count: Array.from(pivot.rows.keys()).filter((key) => selectedKeys.has(key)).length,
        totalCount: pivot.rows.size,
        averageScore: Math.round(
          Array.from(pivot.rows.values()).reduce((total, row) => total + effectiveScore(row), 0) /
            Math.max(pivot.rows.size, 1)
        ),
      })),
      ...selectedRows.map((row) => ({
        id: `ioc:${investigationKey(row)}`,
        kind: 'indicator',
        label: stringValue(row.indicator),
        score: effectiveScore(row),
        sourceCount: Number(row.sourceCount) || rowSources(row).length,
        tagCount: Array.isArray(row.tags) ? row.tags.length : 0,
        row,
      })),
    ];
    const edges = [];
    renderedPivots.forEach((pivot) => {
      pivot.rows.forEach((_row, key) => {
        if (selectedKeys.has(key)) {
          edges.push({
            source: `pivot:${pivot.key}`,
            target: `ioc:${key}`,
            kind: pivot.kind,
          });
        }
      });
    });
    edges.sort((a, b) =>
      a.source.localeCompare(b.source) || a.target.localeCompare(b.target)
    );
    const selectedScores = selectedRows.map(effectiveScore);
    return {
      mode,
      nodes,
      edges,
      stats: {
        pivots: renderedPivots.length,
        indicators: selectedRows.length,
        relationships: edges.length,
        highScore: selectedScores.filter((value) => value >= 80).length,
        corroborated: selectedRows.filter((row) =>
          (Number(row.sourceCount) || rowSources(row).length) >= 2
        ).length,
        averageScore: selectedScores.length
          ? Math.round(selectedScores.reduce((total, value) => total + value, 0) / selectedScores.length)
          : 0,
        tagPivots: renderedPivots.filter((pivot) => pivot.kind === 'tag').length,
        sourcePivots: renderedPivots.filter((pivot) => pivot.kind === 'source').length,
      },
    };
  };

  // Rank evidence already present in the loaded sample; never infer global
  // rarity, attribution, or new activity from absence in a compact feed.
  const buildDiscovery = (value, mode = 'corroborated', now = Date.now() / 1000) => {
    const unique = new Map();
    for (const row of Array.isArray(value) ? value : []) {
      if (lower(row?.type) === 'cve') continue;
      const key = investigationKey(row);
      if (key && !unique.has(key)) unique.set(key, row);
    }
    const rows = Array.from(unique.values());
    // Provider-name tags emitted by our adapters are provenance, including
    // when the source uses an alias (ci_army_list → cins) or a custom name.
    // Keep behavior/product/family tags such as tor, scanning, phishing, c2.
    const sourceNames = new Set([
      'threatfox', 'cins', 'feodo', 'sslbl', 'spamhaus', 'dshield', 'sans-isc',
      'openphish', 'greensnow', 'emerging-threats', 'binarydefense', 'ipsum',
      'urlhaus', 'malwarebazaar',
      ...rows.flatMap(rowSources).flatMap((source) => stringValue(source).split(',')).map(lower),
    ]);
    const ignored = new Set(['aggregated', 'blocklist', 'malicious', 'malware', 'high',
      'critical', 'medium', 'low', 'info', 'unknown', 'ioc', 'multi-list']);
    const tagsFor = (row) => Array.from(new Set(
      (Array.isArray(row.tags) ? row.tags : []).map(lower)
        .filter((tag) => tag && !ignored.has(tag) && !sourceNames.has(tag))
    ));
    const counts = new Map();
    rows.forEach((row) => tagsFor(row).forEach((tag) => counts.set(tag, (counts.get(tag) || 0) + 1)));
    const findings = [];
    for (const row of rows) {
      const sources = Array.from(new Set(rowSources(row).flatMap((source) =>
        stringValue(source).split(',').map(lower)
      ).filter((source) => source && !['unknown', 'n/a', 'none', 'unspecified'].includes(source))));
      let rank;
      let reason;
      let label;
      if (mode === 'recent') {
        const seen = timestamp(row.lastSeen ?? row.last_seen);
        const age = seen == null ? Infinity : now - seen;
        if (age < 0 || age > 86400) continue;
        rank = seen;
        label = 'Seen within 24h';
        reason = 'Last reported within the past 24 hours. A recent sighting does not mean newly discovered activity.';
      } else if (mode === 'uncommon') {
        const rare = tagsFor(row).filter((tag) => counts.get(tag) <= 3)
          .sort((a, b) => counts.get(a) - counts.get(b) || a.localeCompare(b))[0];
        if (!rare) continue;
        rank = 4 - counts.get(rare);
        label = rare;
        reason = `“${rare}” appears on ${counts.get(rare)} of ${rows.length} indicators in this filtered sample. This is sample rarity, not global rarity.`;
      } else {
        if (sources.length < 2) continue;
        rank = sources.length;
        label = `${sources.length} reporting sources`;
        reason = `Reported by ${sources.join(', ')}. Multiple reports provide corroboration, but do not establish source independence.`;
      }
      findings.push({ row, label, reason, rank });
    }
    findings.sort((a, b) => b.rank - a.rank || effectiveScore(b.row) - effectiveScore(a.row) ||
      investigationKey(a.row).localeCompare(investigationKey(b.row)));
    return { total: findings.length, sampleSize: rows.length, findings: findings.slice(0, 6) };
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
    const signal = lower(params.get('signal'));
    const score = Number(params.get('score')) || 0;
    const age = params.get('age') || 'all';
    const state = {
      types: params.getAll('type').map(lower).filter(Boolean),
      sources: params.getAll('source').map(lower).filter(Boolean),
      tags: params.getAll('tag').map(lower).filter(Boolean),
      scoreBands: params.getAll('score_band').map(lower).filter((value) =>
        ['high', 'elevated', 'moderate', 'aging'].includes(value)
      ),
      ageBands: params.getAll('age_band').map(lower).filter((value) =>
        ['day', 'week', 'month', 'older', 'unknown'].includes(value)
      ),
      type: lower(params.get('type')) || 'all',
      source: lower(params.get('source')) || 'all',
      tag: lower(params.get('tag')) || 'all',
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

  // NVD timestamps without offsets are UTC, not the analyst's local time.
  const vulnerabilityDate = (value, now) => {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}(?:$|T)/.test(value)) return null;
    const day = value.slice(0, 10);
    const calendar = Date.parse(`${day}T00:00:00Z`);
    if (!Number.isFinite(calendar) || new Date(calendar).toISOString().slice(0, 10) !== day) return null;
    const utc = value.includes('T') && !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(value) ? `${value}Z` : value;
    const time = Date.parse(utc) / 1000;
    return Number.isFinite(time) && time <= now ? time : null;
  };

  const vulnerabilityFacts = (item, now = Date.now() / 1000) => ({
    added: vulnerabilityDate(item.reports?.cisa_kev?.date_added, now),
    checked: vulnerabilityDate(item.reports?.cisa_kev?.catalog_checked_at, now),
    published: vulnerabilityDate(item.reports?.nvd?.published_at, now),
    modified: vulnerabilityDate(item.reports?.nvd?.modified_at, now),
    rejected: lower(item.reports?.nvd?.status) === 'rejected',
    ransomware: item.exploitation_status === 'known_exploited' && lower(item.reports?.cisa_kev?.ransomware_use) === 'known',
  });

  const filterVulnerabilities = (items, search = '', status = 'all', options = {}) => {
    const query = lower(search).trim();
    const now = options.now ?? Date.now() / 1000;
    const view = ['exploited', 'ransomware', 'kev30', 'published7', 'updated7'].includes(options.view) ? options.view : 'priority';
    const priority = { known_exploited: 0, reported_exploitation: 1, not_established: 2 };
    const recent = (time, days) => time != null && now - time <= days * 86400;
    const orderDate = (item, facts) => view === 'updated7' ? facts.modified
      : view === 'published7' ? facts.published
      : item.exploitation_status === 'known_exploited' ? facts.added : facts.published;
    return items.map((item) => ({ item, facts: vulnerabilityFacts(item, now) })).filter(({ item, facts }) => {
      if (!options.includeRejected && facts.rejected) return false;
      if (status !== 'all' && item.exploitation_status !== status) return false;
      if (view === 'exploited' && item.exploitation_status !== 'known_exploited') return false;
      if (view === 'ransomware' && !facts.ransomware) return false;
      if (view === 'kev30' && (item.exploitation_status !== 'known_exploited' || !recent(facts.added, 30))) return false;
      if (view === 'published7' && !recent(facts.published, 7)) return false;
      if (view === 'updated7' && !recent(facts.modified, 7)) return false;
      const kev = item.reports?.cisa_kev || {};
      const nvd = item.reports?.nvd || {};
      return !query || lower([item.cve_id, item.title, item.description, kev.vendor,
        kev.product, kev.description, nvd.description, ...(item.sources || [])].join(' ')).includes(query);
    }).sort((a, b) => Number(a.facts.rejected) - Number(b.facts.rejected)
      || (view === 'priority' ? (priority[a.item.exploitation_status] ?? 3) - (priority[b.item.exploitation_status] ?? 3) : 0)
      || (orderDate(b.item, b.facts) ?? -Infinity) - (orderDate(a.item, a.facts) ?? -Infinity)
      || a.item.cve_id.localeCompare(b.item.cve_id)).map(({ item }) => item);
  };

  return {
    filterVulnerabilities,
    vulnerabilityFacts,
    compareRows,
    buildCampaignGraph,
    buildDiscovery,
    effectiveScore,
    investigationKey,
    detectionRows,
    matchesRow,
    normaliseInvestigationRows,
    readViewState,
    refang,
    rowsToCsv,
    rowsToSigma,
    rowsToSuricata,
    writeViewUrl,
  };
});
