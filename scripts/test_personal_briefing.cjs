/* Local browser regression: all vulnerability and graph data is synthetic.
 * Serve public/ on port 8765 (or set BASE_URL). Requires Playwright + Chromium.
 */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
(async () => {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}),
  });
  const base = process.env.BASE_URL || 'http://127.0.0.1:8765';
  const key = 'swiftioc-cve-briefing-v1';
  let mode = 'initial';
  const item = (id) => ({ cve_id: `CVE-2026-${id}`, title: 'Synthetic router issue', sources: ['cisa_kev'],
    exploitation_status: 'known_exploited', reports: { cisa_kev: { vendor: 'FixtureVendor', product: 'Router',
      required_action: 'Apply update', ransomware_use: 'Unknown', date_added: '2026-09-01', catalog_checked_at: '2026-09-09T00:00:00Z' },
      nvd: { severity: 'high', status: 'Analyzed' } },
  });
  const setup = async (context) => {
    await context.addInitScript(() => { Date.now = () => Date.parse('2026-09-10T12:00:00Z'); });
    await context.route('**/collections/vulnerabilities.json', (route) => {
      if (mode === 'failure') return route.fulfill({ status: 503, body: 'Unavailable' });
      if (mode === 'malformed') return route.fulfill({ contentType: 'application/json', body: '{"items":' });
      const items = [item(1001), item(1002)];
      if (mode === 'changed') {
        items[0].reports.cisa_kev.ransomware_use = 'Known';
        items[0].reports.cisa_kev.required_action = 'Apply emergency update';
        const added = item(1003); added.reports.cisa_kev.date_added = '2026-09-09'; items.push(added);
      }
      return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ schema_version: 1,
        generated_at: mode === 'older' ? '2026-09-07T00:00:00Z' : mode === 'initial' ? '2026-09-08T00:00:00Z' : '2026-09-09T00:00:00Z', items }) });
    });
    const feed = Array.from({ length: 40 }, (_, index) => JSON.stringify({ indicator: index === 0 ? 'hxxps://fixture[.]example/Payload?key=ABC' : `192[.]0[.]2[.]${index + 1}`, type: index === 0 ? 'url' : 'ipv4',
      source: index < 30 ? 'threatfox_export_json,urlhaus_recent_urls' : index < 35 ? 'ci_army_list' : 'dshield_block',
      tags: index < 30 ? 'threatfox,urlhaus,scanner' : 'scanner', score: index === 0 ? 100 : index < 30 ? 99 : 70,
      last_seen: '2026-09-09T00:00:00Z', confidence: 'high',
    })).join('\n');
    await context.route('**/iocs/dashboard.jsonl', (route) => route.fulfill({ contentType: 'application/x-ndjson', body: feed }));
  };
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    await setup(context);
    const page = await context.newPage(); const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(base);
    await page.locator('[data-vulnerability-status]').filter({ hasText: '2 of 2 CVEs' }).waitFor();
    await page.locator('[data-vulnerability-view="briefing"]').click();
    await page.locator('[data-briefing-vendor]').fill('FixtureVendor');
    await page.locator('[data-briefing-product]').fill('Router');
    await page.locator('[data-briefing-form] button').click();
    const status = page.locator('[data-vulnerability-status]');
    await status.filter({ hasText: '2 watched CVEs' }).waitFor();
    assert.match(await status.innerText(), /0 with new evidence/);
    assert.equal(await page.locator('.vulnerability-card').count(), 2);
    await page.locator('[data-briefing-settings] > summary').click();
    mode = 'changed';
    await page.locator('[data-vulnerability-refresh]').click();
    await status.filter({ hasText: '3 watched CVEs' }).waitFor();
    assert.match(await status.innerText(), /2 with new evidence/);
    const first = page.locator('.vulnerability-card').filter({ has: page.getByRole('heading', { name: 'CVE-2026-1001', exact: true }) });
    assert.match(await first.innerText(), /Added ransomware evidence/);
    assert.match(await first.innerText(), /Remediation changed/);
    await page.getByLabel('Review status for CVE-2026-1003', { exact: true }).selectOption('investigating');
    assert.match(await status.innerText(), /2 with new evidence/);
    await page.locator('[data-briefing-triage]').selectOption('new');
    assert.equal(await page.locator('.vulnerability-card').count(), 2);
    await page.locator('[data-briefing-triage]').selectOption('all');
    await page.reload();
    await status.filter({ hasText: '3 watched CVEs' }).waitFor();
    assert.equal(await page.getByLabel('Review status for CVE-2026-1003', { exact: true }).inputValue(), 'investigating');
    assert.match(await status.innerText(), /2 with new evidence/);
    await page.getByLabel('Review status for CVE-2026-1001', { exact: true }).selectOption('reviewed');
    assert.match(await status.innerText(), /1 with new evidence/);
    await page.locator('[data-briefing-triage]').selectOption('reviewed');
    assert.equal(await page.locator('.vulnerability-card').count(), 1);
    await page.locator('[data-briefing-triage]').selectOption('all');
    if (process.env.SCREENSHOT_DIR) {
      await page.locator('#vulnerabilities').evaluate((el) => el.scrollIntoView({ block: 'start' }));
      await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/personal-briefing-desktop.png` });
    }
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-briefing-export]').click()]);
    const temp = await fs.mkdtemp(path.join(os.tmpdir(), 'swiftioc-briefing-'));
    try {
      const dest = path.join(temp, 'briefing.json'); await download.saveAs(dest);
      const exported = JSON.parse(await fs.readFile(dest, 'utf8'));
      assert.equal(exported.items.length, 3);
      assert.equal(exported.items.find((entry) => entry.cve_id === 'CVE-2026-1003').triage, 'investigating');
    } finally { await fs.rm(temp, { recursive: true }); }
    const baseline = await page.evaluate((key) => localStorage.getItem(key), key);
    for (const problem of ['failure', 'malformed', 'older']) {
      mode = problem; await page.locator('[data-vulnerability-refresh]').click();
      if (problem !== 'older') await status.filter({ hasText: 'Collection unavailable' }).waitFor();
      else await page.locator('[data-briefing-note]').filter({ hasText: 'older than your baseline' }).waitFor();
      assert.equal(await page.locator('[data-briefing-export]').isDisabled(), true);
      assert.equal(await page.evaluate((key) => localStorage.getItem(key), key), baseline);
    }
    mode = 'changed'; await page.locator('[data-vulnerability-refresh]').click();
    await status.filter({ hasText: '3 watched CVEs' }).waitFor();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#vulnerabilities').evaluate((el) => el.scrollIntoView({ block: 'start' }));
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/personal-briefing-mobile.png` });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`${base}/#campaign-graph`);
    const graph = page.locator('[data-campaign-graph]');
    const cins = graph.locator('[data-graph-node][aria-label*="CINS Army"]');
    await cins.waitFor(); assert.equal(await page.locator('[data-campaign-mode]').inputValue(), 'sources');
    await cins.click(); assert.equal(await page.locator('[data-campaign-title]').innerText(), 'CINS Army');
    await page.locator('.campaign-feed-evidence summary').click();
    assert.match(await page.locator('[data-campaign-feed-evidence]').innerText(), /ci_army_list/);
    assert.equal(await graph.locator('[data-graph-node][aria-label*="abuse.ch"]').count(), 1);
    assert.equal(await graph.locator('[data-graph-node][aria-label*="SANS ISC"]').count(), 1);
    // Search raw feed aliases, inspect all connections, and export only real edges.
    await graph.locator('[data-graph-node][aria-label*="abuse.ch"]').click();
    const relatedCount = Number((await page.locator('[data-campaign-related-heading]').innerText()).match(/\d+/)[0]);
    assert.ok(relatedCount > 10);
    assert.equal(await page.locator('[data-campaign-related-list] button').count(), relatedCount);
    const [graphDownload] = await Promise.all([page.waitForEvent('download'), page.locator('[data-campaign-export]').click()]);
    const graphTemp = await fs.mkdtemp(path.join(os.tmpdir(), 'swiftioc-graph-'));
    try {
      const dest = path.join(graphTemp, 'graph.json'); await graphDownload.saveAs(dest);
      const exported = JSON.parse(await fs.readFile(dest, 'utf8'));
      assert.equal(exported.scope, 'selected-neighborhood');
      assert.equal(exported.counts.indicators, relatedCount);
      assert.equal(exported.edges.length, relatedCount);
      assert.ok(exported.edges.every((edge) => edge.source === exported.selected_node));
      const ids = new Set(exported.nodes.map((node) => node.id));
      assert.ok(exported.edges.every((edge) => ids.has(edge.source) && ids.has(edge.target)));
    } finally { await fs.rm(graphTemp, { recursive: true }); }
    await page.locator('[data-campaign-search]').fill('192.0.2.31');
    assert.equal(await page.locator('[data-campaign-search-results] button').count(), 1);
    await page.locator('[data-campaign-search-results] button').click();
    assert.equal(await page.locator('[data-campaign-title]').innerText(), '192[.]0[.]2[.]31');
    await page.locator('[data-campaign-search]').fill('https://fixture.example/Payload?key=ABC');
    assert.equal(await page.locator('[data-campaign-search-results] button').count(), 1);
    await page.locator('[data-campaign-search-results] button').click();
    assert.equal(await page.locator('[data-campaign-title]').innerText(), 'hxxps://fixture[.]example/Payload?key=ABC');
    await page.locator('[data-campaign-search]').fill('ci_army_list');
    assert.equal(await page.locator('[data-campaign-search-results] button').count(), 6);
    await page.locator('[data-campaign-search-results] button').filter({ hasText: 'CINS Army' }).click();
    assert.equal(await page.locator('[data-campaign-title]').innerText(), 'CINS Army');
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('[data-campaign-reset]').isDisabled(), true);
    assert.equal(await graph.locator('.is-dimmed').count(), 0);
    await page.locator('[data-campaign-search]').fill('no-such-fixture');
    assert.match(await page.locator('[data-campaign-search-status]').innerText(), /0 matching nodes/);
    assert.equal(await page.locator('[data-campaign-search-results] button').count(), 0);
    await cins.click();
    await page.locator('[data-campaign-reset]').click();
    assert.equal(await page.locator('[data-campaign-search]').inputValue(), '');
    assert.equal(await page.locator('[data-campaign-export]').innerText(), 'Export graph JSON');
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.setViewportSize({ width: 1440, height: 1000 });
    if (process.env.SCREENSHOT_DIR) {
      await page.locator('#campaign-graph').scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/provider-graph.png` });
    }
    await page.evaluate(() => window.dispatchEvent(new CustomEvent('swiftioc:preview-filtered', { detail: { rows: [] } })));
    assert.equal(await page.locator('[data-campaign-export]').isDisabled(), true);
    assert.equal(await page.locator('[data-campaign-related]').isVisible(), false);

    assert.deepEqual(errors, []);
    // Malformed saved state cannot turn every historical CVE into a change.
    await page.evaluate((key) => localStorage.setItem(key, '{broken'), key);
    await page.goto(base); await status.filter({ hasText: '3 of 3 CVEs' }).waitFor();
    assert.match(await page.locator('[data-briefing-note]').innerText(), /fresh baseline/);
    const blocked = await browser.newContext(); await setup(blocked);
    await blocked.addInitScript(() => { Storage.prototype.setItem = () => { throw new Error('Storage blocked'); }; });
    const volatile = await blocked.newPage(); await volatile.goto(base);
    await volatile.locator('[data-vulnerability-status]').filter({ hasText: '3 of 3 CVEs' }).waitFor();
    await volatile.locator('[data-vulnerability-view="briefing"]').click();
    await volatile.locator('[data-briefing-vendor]').fill('FixtureVendor');
    await volatile.locator('[data-briefing-form] button').click();
    assert.match(await volatile.locator('[data-briefing-note]').innerText(), /this tab only/);
    assert.match(await volatile.locator('[data-vulnerability-status]').innerText(), /0 with new evidence/);
    console.log('PASS: briefing baselines, material changes, persistent triage, filtered JSON export, failed/stale refreshes, malformed/blocked storage, mobile layout, and genuine provider diversity.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
