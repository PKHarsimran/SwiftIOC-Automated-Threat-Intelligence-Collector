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

  // Import is all-or-nothing: storage recovery may discard bad rows, but an
  // explicit analyst import must never silently lose records or exceed capacity.
  const mergeInvestigationImport = (current, value) => {
    if (!Array.isArray(value) || !value.length || value.length > 50) {
      throw new Error('Choose a queue JSON export containing 1–50 records.');
    }
    const strings = ['confidence', 'source', 'firstSeen', 'lastSeen', 'reference', 'context', 'tlp'];
    value.forEach((row, index) => {
      const valid = row && typeof row === 'object' && !Array.isArray(row)
        && typeof row.indicator === 'string' && row.indicator.trim().length > 0 && row.indicator.length <= 2048
        && typeof row.type === 'string' && row.type.trim().length > 0 && row.type.length <= 64
        && strings.every((field) => row[field] === undefined || typeof row[field] === 'string')
        && ['tags', 'sourceList'].every((field) => row[field] === undefined || (Array.isArray(row[field])
          && row[field].length <= (field === 'tags' ? 50 : 25) && row[field].every((item) => typeof item === 'string')))
        && (row.score === undefined || (typeof row.score === 'number' && Number.isFinite(row.score) && row.score >= 0 && row.score <= 100));
      if (!valid) throw new Error(`Record ${index + 1} is not a valid queue export. Nothing was imported.`);
    });
    const merged = normaliseInvestigationRows([...current, ...value], 250);
    if (merged.length > 50) throw new Error(`This import would use ${merged.length} of 50 slots. Remove some queued indicators first.`);
    const added = merged.length - current.length;
    return { rows: merged, added, duplicates: value.length - added };
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

  const rowsToSpl = (value, options = {}) => {
    const index = stringValue(options.index ?? 'YOUR_INDEX');
    const earliest = options.earliest ?? '-24h';
    const names = ['src_ip', 'dest_ip', 'query', 'url', 'md5', 'sha1', 'sha256'];
    const mapping = Object.fromEntries(names.map((name) => [name, stringValue(options.fields?.[name] ?? name)]));
    let error = '';
    if (!/^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,99}$/.test(index)) error = 'Enter one index name using letters, numbers, underscores or hyphens.';
    else if (!['-15m', '-1h', '-24h', '-7d', '-30d'].includes(earliest)) error = 'Choose one of the supported time ranges.';
    else if (Object.values(mapping).some((name) => !/^[a-zA-Z_][a-zA-Z0-9_.]{0,99}$/.test(name) || name === 'swiftioc_matches')) error = 'Field names must start with a letter or underscore and contain only letters, numbers, underscores or dots. swiftioc_matches is reserved.';
    if (error) return { included: 0, skipped: [], spl: '', error };
    const field = (name) => `'${mapping[name]}'`;
    const outputFields = [...new Set(['_time', 'host', 'user', 'action', ...Object.values(mapping)])].map((name) => JSON.stringify(name)).join(' ');
    const rows = Array.isArray(value) ? value : [];
    const clauses = [], skipped = [], seen = new Set();
    for (const row of rows) {
      const type = lower(row?.type);
      let indicator = refang(row?.indicator);
      let condition = '';
      const quote = JSON.stringify;
      if (!indicator || /[\u0000-\u001f\u007f]/.test(indicator)) { skipped.push(row); continue; }
      if (['ipv4', 'ipv6', 'ipv4_cidr', 'ipv6_cidr', 'domain'].includes(type)) {
        const validated = detectionRows([row])[0];
        if (validated) {
          indicator = validated.indicator.toLowerCase();
          if (type === 'domain') condition = `lower(rtrim(trim(${field('query')}), "."))=${quote(indicator)}`;
          else {
            const network = type.endsWith('_cidr') ? indicator : `${indicator}/${type === 'ipv6' ? 128 : 32}`;
            condition = `(cidrmatch(${quote(network)}, ${field('src_ip')}) OR cidrmatch(${quote(network)}, ${field('dest_ip')}))`;
          }
        }
      } else if (['md5', 'sha1', 'sha256'].includes(type)) {
        const length = { md5: 32, sha1: 40, sha256: 64 }[type];
        if (new RegExp(`^[a-f0-9]{${length}}$`, 'i').test(indicator)) {
          indicator = indicator.toLowerCase();
          condition = `lower(trim(${field(type)}))=${quote(indicator)}`;
        }
      } else if (type === 'url') {
        try {
          if (['http:', 'https:'].includes(new URL(indicator).protocol)) condition = `${field('url')}=${quote(indicator)}`;
        } catch { /* Unsupported URL remains in the skipped list. */ }
      }
      if (!condition) { skipped.push(row); continue; }
      const key = `${type}:${indicator}`;
      if (seen.has(key)) continue;
      seen.add(key);
      clauses.push(`    if(${condition}, ${quote(key)}, null())`);
    }
    return { included: seen.size, skipped,
      spl: clauses.length ? `index=${index} earliest=${earliest} latest=now\n`
        + `| fields ${outputFields}\n`
        + '| eval swiftioc_matches=mvappend(\n' + clauses.join(',\n') + ',\n    null())\n'
        + '| where mvcount(swiftioc_matches)>0\n'
        + `| table ${outputFields} swiftioc_matches\n` : '' };
  };

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

  // Explicit aliases from the shipped adapters. Unknown/custom feeds keep
  // their identity; similar spelling is not evidence of a common publisher.
  const providerGroups = [
    ['abuse.ch', 'abuse.ch', ['threatfox_export_json', 'threatfox_recent', 'threatfox', 'urlhaus_recent_urls', 'urlhaus', 'malwarebazaar_recent', 'malwarebazaar', 'feodo_ipblocklist', 'feodo', 'sslbl_ja3', 'sslbl']],
    ['cins', 'CINS Army', ['ci_army_list', 'cins']],
    ['spamhaus', 'Spamhaus', ['spamhaus_drop', 'spamhaus_drop_v6', 'spamhaus']],
    ['dshield', 'SANS ISC / DShield', ['dshield_block', 'dshield', 'sans-isc']],
    ['blocklist.de', 'blocklist.de', ['blocklist_de_ssh', 'blocklist_de_all']],
    ['greensnow', 'GreenSnow', ['greensnow_blocklist', 'greensnow']],
    ['openphish', 'OpenPhish', ['openphish_feed', 'openphish']],
    ['emerging-threats', 'Emerging Threats', ['et_compromised', 'emerging-threats']],
    ['binarydefense', 'Binary Defense', ['binarydefense_banlist', 'binarydefense']],
    ['ipsum', 'IPsum (aggregate)', ['ipsum_level5', 'ipsum'], 'aggregate'],
    ['tor', 'Tor exit directory', ['tor_exit_nodes'], 'context'],
  ];
  const providerAliases = new Map(providerGroups.flatMap(([id, label, aliases, role = 'reporting']) =>
    aliases.map((alias) => [alias, { id, label, role }])));
  const sourceProviders = (row) => {
    const providers = new Map();
    rowSources(row).flatMap((value) => stringValue(value).split(',')).forEach((value) => {
      const raw = stringValue(value);
      if (['', 'n/a', 'none', 'unknown', 'unspecified'].includes(lower(raw))) return;
      const identity = providerAliases.get(lower(raw)) || { id: lower(raw), label: raw, role: 'unmapped' };
      const provider = providers.get(identity.id) || { ...identity, feeds: [] };
      if (!provider.feeds.some((feed) => lower(feed) === lower(raw))) provider.feeds.push(raw);
      providers.set(identity.id, provider);
    });
    return [...providers.values()];
  };
  const graphProviderCount = (row) => sourceProviders(row).filter((provider) => provider.role === 'reporting').length;

  const graphNodeMatches = (node, value) => {
    const query = lower(value);
    if (!query || !node) return false;
    const literal = [node.label, node.row?.type, ...(node.feeds || []),
      ...(node.providers || []).flatMap((provider) => [provider.label, ...provider.feeds]),
      ...(node.row?.tags || []),
    ].map(lower);
    if (literal.some((field) => field.includes(query))) return true;
    // Refang only IOC values. Provider and tag text must retain its literal
    // meaning even when it happens to contain defanging-like punctuation.
    return node.kind === 'indicator' && lower(refang(node.label)).includes(lower(refang(query)));
  };

  const buildCampaignGraph = (value, options = {}) => {
    const rows = Array.isArray(value) ? value.filter((row) => row?.indicator && lower(row.type) !== 'cve') : [];
    const mode = ['all', 'tags', 'sources'].includes(options.mode) ? options.mode : 'all';
    const maxPivots = Math.max(1, Math.min(Number(options.maxPivots) || 6, 10));
    const maxIndicators = Math.max(2, Math.min(Number(options.maxIndicators) || 24, 50));
    const ignoredTags = new Set([
      'aggregated', 'blocklist', 'critical', 'high', 'info', 'ioc', 'low',
      'malicious', 'malware', 'medium', 'threat-intel', 'threat intelligence',
      'json', 'csv', 'txt', 'export', 'export_json', 'multi-list',
    ]);
    const sourceNames = new Set([...providerAliases.keys(), ...providerGroups.map(([id]) => id), ...rows.flatMap((row) => rowSources(row).flatMap((value) => stringValue(value).split(',')).map(lower))]);
    const pivots = new Map();

    const addPivot = (kind, label, row, provider = null) => {
      const clean = stringValue(label);
      if (!clean) return;
      const key = `${kind}:${provider?.id || clean.toLowerCase()}`;
      const pivot = pivots.get(key) || { key, kind, label: clean, role: provider?.role, rows: new Map(), feeds: new Set(), score: 0 };
      provider?.feeds.forEach((feed) => pivot.feeds.add(feed));
      const rowKey = investigationKey(row);
      if (!rowKey || pivot.rows.has(rowKey)) return;
      pivot.rows.set(rowKey, row);
      pivot.score += effectiveScore(row) + Math.min(graphProviderCount(row), 5) * 5;
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
        sourceProviders(row).slice(0, 25).forEach((provider) => {
          if (provider.role !== 'context') addPivot('source', provider.label, row, provider);
        });
      }
    });

    const rankedPivots = Array.from(pivots.values())
      .filter((pivot) => pivot.rows.size >= 2)
      .sort((a, b) =>
        (b.rows.size * 100 + b.score / b.rows.size) -
          (a.rows.size * 100 + a.score / a.rows.size) ||
        a.key.localeCompare(b.key)
      )
;
    const selectedPivots = [];
    if (mode === 'all') {
      const providers = rankedPivots.filter((pivot) => pivot.kind === 'source');
      const tags = rankedPivots.filter((pivot) => pivot.kind === 'tag');
      for (let i = 0; selectedPivots.length < maxPivots && i < rankedPivots.length; i += 1) {
        for (const pivot of [providers[i], tags[i]]) {
          if (pivot && selectedPivots.length < maxPivots) selectedPivots.push(pivot);
        }
      }
    } else selectedPivots.push(...rankedPivots.slice(0, maxPivots));

    // Round-robin selection gives smaller providers a place in a bounded graph.
    // It never creates providers or links absent from the loaded sample.
    const selectedByKey = new Map();
    const candidates = selectedPivots.map((pivot) => Array.from(pivot.rows.values()).sort((a, b) =>
      effectiveScore(b) - effectiveScore(a) || graphProviderCount(b) - graphProviderCount(a) ||
      stringValue(a.indicator).localeCompare(stringValue(b.indicator))));
    while (selectedByKey.size < maxIndicators) {
      let added = false;
      for (const list of candidates) {
        const row = list.find((candidate) => !selectedByKey.has(investigationKey(candidate)));
        if (row && selectedByKey.size < maxIndicators) {
          selectedByKey.set(investigationKey(row), row);
          added = true;
        }
      }
      if (!added) break;
    }
    const selectedRows = [...selectedByKey.values()];
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
        role: pivot.role,
        feeds: [...pivot.feeds].sort(),
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
        sourceCount: graphProviderCount(row),
        providers: sourceProviders(row),
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
          graphProviderCount(row) >= 2
        ).length,
        averageScore: selectedScores.length
          ? Math.round(selectedScores.reduce((total, value) => total + value, 0) / selectedScores.length)
          : 0,
        tagPivots: renderedPivots.filter((pivot) => pivot.kind === 'tag').length,
        sourcePivots: renderedPivots.filter((pivot) => pivot.kind === 'source').length,
        availableProviders: rankedPivots.filter((pivot) => pivot.kind === 'source').length,
        mappedProviders: renderedPivots.filter((pivot) => pivot.role === 'reporting').length,
        aggregates: renderedPivots.filter((pivot) => pivot.role === 'aggregate').length,
        unmappedFeeds: renderedPivots.filter((pivot) => pivot.role === 'unmapped').length,
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

  const readViewState = (search = '', hash = '', defaultLimit = 12) => {
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
      limit: [6, 12, 25, 50, 100].includes(Number(params.get('rows')))
        ? Number(params.get('rows'))
        : ([6, 12].includes(defaultLimit) ? defaultLimit : 12),
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

  const writeViewUrl = (currentUrl, state, includeSearch = false, defaultLimit = 12) => {
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
    if (includeSearch || state.limit !== defaultLimit) url.searchParams.set('rows', String(state.limit));
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
      if (/^cve-\d{4}-\d{4,}$/.test(query)) return lower(item.cve_id) === query;
      return !query || lower([item.cve_id, item.title, item.description, kev.vendor,
        kev.product, kev.description, nvd.description, ...(item.sources || [])].join(' ')).includes(query);
    }).sort((a, b) => Number(a.facts.rejected) - Number(b.facts.rejected)
      || (view === 'priority' ? (priority[a.item.exploitation_status] ?? 3) - (priority[b.item.exploitation_status] ?? 3) : 0)
      || (orderDate(b.item, b.facts) ?? -Infinity) - (orderDate(a.item, a.facts) ?? -Infinity)
      || a.item.cve_id.localeCompare(b.item.cve_id)).map(({ item }) => item);
  };

  const watchKey = (watch) => JSON.stringify([lower(watch.vendor).trim(), lower(watch.product).trim()]);
  const matchesWatch = (item, watch) => {
    const kev = item.reports?.cisa_kev;
    return typeof kev?.vendor === 'string' && lower(kev.vendor).trim() === lower(watch.vendor).trim()
      && (!watch.product || (typeof kev.product === 'string' && lower(kev.product).trim() === lower(watch.product).trim()));
  };
  const briefingEvidence = (item) => ({
    exploitation: item.exploitation_status,
    ransomware: vulnerabilityFacts(item).ransomware,
    action: typeof item.reports?.cisa_kev?.required_action === 'string' ? item.reports.cisa_kev.required_action : '',
    due: typeof item.reports?.cisa_kev?.due_date === 'string' ? item.reports.cisa_kev.due_date : '',
    rejected: lower(item.reports?.nvd?.status) === 'rejected',
    severity: typeof item.reports?.nvd?.severity === 'string' ? lower(item.reports.nvd.severity) : '',
  });
  const emptyBriefing = () => ({ version: 1, watches: [], records: {}, snapshotAt: null });
  const normaliseBriefing = (value, now = Date.now() / 1000) => {
    if (!value || value.version !== 1 || !Array.isArray(value.watches) || value.watches.length > 20
      || !value.records || typeof value.records !== 'object' || Array.isArray(value.records)
      || Object.keys(value.records).length > 5000
      || (value.snapshotAt !== null && (typeof value.snapshotAt !== 'number' || !Number.isFinite(value.snapshotAt)
        || value.snapshotAt < 0 || value.snapshotAt > now + 300))) return null;
    const watches = [];
    for (const watch of value.watches) {
      if (!watch || typeof watch.vendor !== 'string' || !watch.vendor.trim() || watch.vendor.length > 100
        || typeof watch.product !== 'string' || watch.product.length > 160) return null;
      const clean = { vendor: watch.vendor.trim(), product: watch.product.trim(), ready: watch.ready === true };
      if (!watches.some((entry) => watchKey(entry) === watchKey(clean))) watches.push(clean);
    }
    const records = {};
    for (const [id, record] of Object.entries(value.records)) {
      const evidence = record?.evidence;
      if (evidence === null && /^CVE-[0-9]{4}-[0-9]{4,19}$/.test(id) && ['unreviewed', 'investigating'].includes(record.triage)) {
        records[id] = { evidence: null, triage: record.triage };
        continue;
      }
      if (!/^CVE-[0-9]{4}-[0-9]{4,19}$/.test(id) || !evidence
        || !['known_exploited', 'reported_exploitation', 'not_established'].includes(evidence.exploitation)
        || typeof evidence.ransomware !== 'boolean' || typeof evidence.rejected !== 'boolean'
        || !['action', 'due', 'severity'].every((key) => typeof evidence[key] === 'string' && evidence[key].length <= 20000)
        || !['unreviewed', 'investigating', 'reviewed'].includes(record.triage)) return null;
      records[id] = { evidence: { exploitation: evidence.exploitation, ransomware: evidence.ransomware,
        action: evidence.action, due: evidence.due, rejected: evidence.rejected, severity: evidence.severity }, triage: record.triage };
    }
    if (value.snapshotAt === null && Object.keys(records).length) return null;
    return { version: 1, watches, records, snapshotAt: value.snapshotAt };
  };
  const briefingChanges = (previous, current) => {
    if (!previous) return ['New to your watched collection'];
    const changes = [];
    if (previous.exploitation !== current.exploitation) changes.push(current.exploitation === 'known_exploited'
      ? 'Added CISA KEV evidence' : 'Exploitation classification changed');
    if (previous.ransomware !== current.ransomware) changes.push(current.ransomware ? 'Added ransomware evidence' : 'Ransomware evidence changed');
    if (previous.action !== current.action) changes.push('Remediation changed');
    if (previous.due !== current.due) changes.push('CISA due date changed');
    if (previous.rejected !== current.rejected) changes.push(current.rejected ? 'NVD record rejected' : 'NVD rejection status changed');
    if (previous.severity !== current.severity) changes.push('Severity changed');
    return changes;
  };
  const seedBriefing = (items, state, snapshotAt) => {
    const pending = state.watches.filter((watch) => !watch.ready);
    const records = { ...state.records };
    const readyWatches = state.watches.filter((watch) => watch.ready);
    let seeded = false;
    const watches = state.watches.map((watch) => {
      if (watch.ready || !items.some((item) => matchesWatch(item, watch))) return watch;
      seeded = true;
      return { ...watch, ready: true };
    });
    for (const item of items) {
      if (pending.some((watch) => matchesWatch(item, watch)) && !readyWatches.some((watch) => matchesWatch(item, watch))) {
        records[item.cve_id] = { evidence: briefingEvidence(item), triage: 'unreviewed' };
      }
    }
    return { ...state, watches, records, snapshotAt: seeded ? snapshotAt : state.snapshotAt };
  };
  const buildBriefing = (items, state, snapshotAt) => {
    const comparable = state.snapshotAt !== null && snapshotAt >= state.snapshotAt;
    return items.filter((item) => state.watches.some((watch) => matchesWatch(item, watch))).map((item) => {
      const previous = state.records[item.cve_id];
      const changes = comparable ? briefingChanges(previous?.evidence, briefingEvidence(item)) : [];
      return { item, changes, triage: previous?.triage === 'investigating' ? 'investigating'
        : changes.length ? 'new' : previous?.triage || 'unreviewed' };
    }).sort((a, b) => Number(b.changes.length > 0) - Number(a.changes.length > 0)
      || Number(b.item.exploitation_status === 'known_exploited') - Number(a.item.exploitation_status === 'known_exploited')
      || (vulnerabilityFacts(b.item).added ?? 0) - (vulnerabilityFacts(a.item).added ?? 0)
      || a.item.cve_id.localeCompare(b.item.cve_id));
  };

  return {
    emptyBriefing, normaliseBriefing, matchesWatch, watchKey, briefingEvidence, briefingChanges, seedBriefing, buildBriefing,
    filterVulnerabilities,
    vulnerabilityFacts,
    compareRows,
    buildCampaignGraph,
    graphNodeMatches,
    sourceProviders,
    buildDiscovery,
    effectiveScore,
    investigationKey,
    detectionRows,
    matchesRow,
    normaliseInvestigationRows,
    mergeInvestigationImport,
    readViewState,
    refang,
    rowsToCsv,
    rowsToSigma,
    rowsToSpl,
    rowsToSuricata,
    writeViewUrl,
  };
});
