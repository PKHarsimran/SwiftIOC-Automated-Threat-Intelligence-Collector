<link rel="stylesheet" href="../assets/styles.css">
<div class="page-wrapper">
  <nav class="top-nav" aria-label="Primary">
    <div class="brand">
      <strong>SwiftIOC Diagnostics</strong>
      <span>Run metadata and collection health</span>
    </div>
    <div class="action-links">
      <a href="../index.md" class="button-link">Overview</a>
      <a href="#run-health" class="button-link">Run Health</a>
      <a href="#sources" class="button-link">Sources</a>
      <a href="#tags" class="button-link">Tags</a>
      <a href="REPORT.md" class="button-link">Full Report</a>
    </div>
  </nav>

  <header class="page-header">
    <div>
      <h1 class="section-title">SwiftIOC IOC Summary</h1>
      <p class="section-subtitle">Detailed breakdown of the most recent SwiftIOC aggregation, including per-source performance and tag distribution.</p>
      <p class="updated-at">Generated 2025-11-10T00:38:51Z</p>
    </div>
  </header>

  <section id="run-health">
    <h2 class="section-title">Run Health Snapshot</h2>
    <div class="card-grid">
      <article class="stat-card">
        <h3>Total Indicators</h3>
        <div class="stat-value">2,497</div>
        <p class="action-description">Total number of indicators published after normalisation and de-duplication.</p>
      </article>
      <article class="stat-card">
        <h3>Duplicates Removed</h3>
        <div class="stat-value">0</div>
        <p class="action-description">Indicators that were identified as duplicates across sources and filtered out.</p>
      </article>
      <article class="stat-card">
        <h3>Active Sources</h3>
        <div class="stat-value">4</div>
        <p class="action-description">Feeds successfully queried during the latest scheduled run.</p>
      </article>
      <article class="stat-card">
        <h3>Indicator Types</h3>
        <div class="stat-value">4</div>
        <p class="action-description">Distinct IOC formats identified within the aggregated dataset.</p>
      </article>
    </div>
  </section>

  <section id="timeline">
    <h2 class="section-title">Timeline Details</h2>
    <div class="card-grid">
      <article class="stat-card">
        <h3>Earliest First Seen</h3>
        <div class="stat-value">2025-11-08<br><span class="badge">00:38:37Z</span></div>
        <p class="action-description">Oldest IOC retained in the analysis window for this run.</p>
      </article>
      <article class="stat-card">
        <h3>Newest First Seen</h3>
        <div class="stat-value">2025-11-10<br><span class="badge">00:34:46Z</span></div>
        <p class="action-description">Most recent IOC observed across all activated sources.</p>
      </article>
      <article class="stat-card">
        <h3>Multi-source Overlaps</h3>
        <div class="stat-value">0</div>
        <p class="action-description">IOCs confirmed independently by multiple feeds in this cycle.</p>
      </article>
    </div>
  </section>

  <section id="sources">
    <h2 class="section-title">Per-source Totals</h2>
    <p class="section-subtitle">Use these counts to identify which feeds are most active or may require follow-up.</p>
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

  <section id="tags">
    <h2 class="section-title">Top Tags</h2>
    <p class="section-subtitle">Tags highlight dominant malware families or tooling associated with the collected IOCs.</p>
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

  <section id="follow-up">
    <h2 class="section-title">Next Steps</h2>
    <div class="actions-grid">
      <article class="action-card">
        <h3>Review Full Diagnostics</h3>
        <p class="action-description">Open the comprehensive diagnostic report for detailed collection logs, source errors, and processing notes.</p>
        <div class="action-links">
          <a class="button-link" href="REPORT.md">Read REPORT.md</a>
        </div>
      </article>
      <article class="action-card">
        <h3>Return to Overview</h3>
        <p class="action-description">Navigate back to the main snapshot for high-level statistics and download actions.</p>
        <div class="action-links">
          <a class="button-link" href="../index.md">Back to Snapshot</a>
        </div>
      </article>
    </div>
  </section>

  <footer class="footer">
    <p>Need historical context? Consult the archived reports or regenerate data using the SwiftIOC collection pipeline.</p>
  </footer>
</div>
