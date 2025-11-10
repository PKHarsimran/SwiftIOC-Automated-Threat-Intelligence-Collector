<link rel="stylesheet" href="assets/styles.css">
<div class="page-wrapper">
  <header class="page-header">
    <nav class="top-nav" aria-label="Primary">
      <div class="brand">
        <strong>SwiftIOC</strong>
        <span>Automated Threat Intelligence Collector</span>
      </div>
      <div class="action-links">
        <a href="#highlights" class="button-link">Highlights</a>
        <a href="#sources" class="button-link">Sources</a>
        <a href="#indicator-types" class="button-link">Indicator Types</a>
        <a href="#actions" class="button-link">Data Actions</a>
        <a href="diagnostics/summary.md" class="button-link">Diagnostics</a>
      </div>
    </nav>
    <div>
      <h1 class="section-title">SwiftIOC Threat Intelligence Snapshot</h1>
      <p class="section-subtitle">Automatically generated snapshot from the most recent SwiftIOC collection run, designed for quick situational awareness and rapid access to downloadable intelligence feeds.</p>
      <p class="updated-at">Generated 2025-11-10T00:38:51Z</p>
    </div>
  </header>

  <section id="highlights">
    <h2 class="section-title">Operational Highlights</h2>
    <p class="section-subtitle">A summary of the current indicator of compromise (IOC) landscape derived from all enabled sources.</p>
    <div class="card-grid">
      <article class="stat-card">
        <h3>Total Indicators</h3>
        <div class="stat-value">2,497</div>
        <p class="action-description">Unique IOCs collected during the latest cycle.</p>
      </article>
      <article class="stat-card">
        <h3>Sources Reporting</h3>
        <div class="stat-value">4</div>
        <p class="action-description">Active intelligence feeds that produced data in this run.</p>
      </article>
      <article class="stat-card">
        <h3>Indicator Types</h3>
        <div class="stat-value">4</div>
        <p class="action-description">Distinct IOC formats identified across the feeds.</p>
      </article>
      <article class="stat-card">
        <h3>Duplicates Removed</h3>
        <div class="stat-value">0</div>
        <p class="action-description">Indicators deduplicated to maintain a clean dataset.</p>
      </article>
    </div>
  </section>

  <section id="timeline">
    <h2 class="section-title">Collection Timeline</h2>
    <div class="card-grid">
      <article class="stat-card">
        <h3>Earliest First Seen</h3>
        <div class="stat-value">2025-11-08<br><span class="badge">00:38:37Z</span></div>
        <p class="action-description">Oldest IOC sighting retained in the active window.</p>
      </article>
      <article class="stat-card">
        <h3>Newest First Seen</h3>
        <div class="stat-value">2025-11-10<br><span class="badge">00:34:46Z</span></div>
        <p class="action-description">Most recent IOC discovery across all sources.</p>
      </article>
      <article class="stat-card">
        <h3>Multi-source Overlaps</h3>
        <div class="stat-value">0</div>
        <p class="action-description">IOCs independently confirmed by more than one feed.</p>
      </article>
    </div>
  </section>

  <section id="sources">
    <h2 class="section-title">Per-source Totals</h2>
    <p class="section-subtitle">Understand which feeds are contributing the most intelligence at a glance.</p>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col" style="text-align:right">Indicators</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>urlhaus_recent_urls</td>
            <td style="text-align:right">1,635</td>
          </tr>
          <tr>
            <td>malwarebazaar_recent</td>
            <td style="text-align:right">769</td>
          </tr>
          <tr>
            <td>sslbl_ja3</td>
            <td style="text-align:right">92</td>
          </tr>
          <tr>
            <td>feodo_ipblocklist</td>
            <td style="text-align:right">1</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <section id="indicator-types">
    <h2 class="section-title">Indicator Types</h2>
    <p class="section-subtitle">Breakdown of IOC formats to support filtering and response planning.</p>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th scope="col">Type</th>
            <th scope="col" style="text-align:right">Indicators</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>url</td>
            <td style="text-align:right">1,635</td>
          </tr>
          <tr>
            <td>sha256</td>
            <td style="text-align:right">769</td>
          </tr>
          <tr>
            <td>ja3</td>
            <td style="text-align:right">92</td>
          </tr>
          <tr>
            <td>ipv4</td>
            <td style="text-align:right">1</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <section id="top-tags">
    <h2 class="section-title">Top Tags</h2>
    <p class="section-subtitle">Most prevalent threat tags assigned to indicators in the latest sweep.</p>
    <div class="table-wrapper">
      <table>
        <thead>
          <tr>
            <th scope="col">Tag</th>
            <th scope="col" style="text-align:right">Indicators</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>malware</td>
            <td style="text-align:right">2,405</td>
          </tr>
          <tr>
            <td>Mirai</td>
            <td style="text-align:right">496</td>
          </tr>
          <tr>
            <td>sslbl</td>
            <td style="text-align:right">92</td>
          </tr>
          <tr>
            <td>tls</td>
            <td style="text-align:right">92</td>
          </tr>
          <tr>
            <td>fingerprint</td>
            <td style="text-align:right">92</td>
          </tr>
          <tr>
            <td>Rhadamanthys</td>
            <td style="text-align:right">20</td>
          </tr>
          <tr>
            <td>Ngioweb</td>
            <td style="text-align:right">14</td>
          </tr>
          <tr>
            <td>AgentTesla</td>
            <td style="text-align:right">11</td>
          </tr>
          <tr>
            <td>RemcosRAT</td>
            <td style="text-align:right">10</td>
          </tr>
          <tr>
            <td>XWorm</td>
            <td style="text-align:right">9</td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>

  <section id="actions">
    <h2 class="section-title">Data Actions</h2>
    <p class="section-subtitle">Choose the format that best fits your workflow. Each action card explains what you get before you download.</p>
    <div class="actions-grid">
      <article class="action-card">
        <h3>Download CSV</h3>
        <p class="action-description">Exports all current indicators in comma-separated format. Ideal for spreadsheets, SIEM ingestion, and manual review.</p>
        <div class="action-links">
          <a class="button-link" href="iocs/latest.csv">Get CSV</a>
        </div>
      </article>
      <article class="action-card">
        <h3>Download TSV</h3>
        <p class="action-description">Tab-delimited indicators for tooling that expects whitespace-separated values with consistent quoting.</p>
        <div class="action-links">
          <a class="button-link" href="iocs/latest.tsv">Get TSV</a>
        </div>
      </article>
      <article class="action-card">
        <h3>JSON Feed</h3>
        <p class="action-description">Machine-readable JSON document containing the full indicator payload, suitable for scripting and automation.</p>
        <div class="action-links">
          <a class="button-link" href="iocs/latest.json">Download JSON</a>
          <a class="button-link" href="iocs/latest.jsonl">Stream (JSONL)</a>
        </div>
      </article>
      <article class="action-card">
        <h3>STIX 2.1 Bundle</h3>
        <p class="action-description">Standards-compliant STIX bundle for sharing threat intelligence with TIPs and platforms that ingest STIX objects.</p>
        <div class="action-links">
          <a class="button-link" href="iocs/stix2.json">Download STIX</a>
        </div>
      </article>
      <article class="action-card">
        <h3>Diagnostics Report</h3>
        <p class="action-description">Dive deeper into collection health, failures, and per-source diagnostics to troubleshoot feed availability.</p>
        <div class="action-links">
          <a class="button-link" href="diagnostics/summary.md">View Diagnostics</a>
        </div>
      </article>
      <article class="action-card">
        <h3>Raw Data Directory</h3>
        <p class="action-description">Browse the published IOC folder directly to integrate with external tooling or scripted downloads.</p>
        <div class="action-links">
          <a class="button-link" href="iocs/">Open Directory</a>
        </div>
      </article>
    </div>
  </section>

  <footer class="footer">
    <p>SwiftIOC automatically harvests, normalises, and publishes threat intelligence on a rolling basis. For implementation details, explore the repository README.</p>
    <p><a href="diagnostics/summary.md" class="button-link">Diagnostics Summary</a> · <a href="diagnostics/REPORT.md" class="button-link">Full Report</a></p>
  </footer>
</div>
