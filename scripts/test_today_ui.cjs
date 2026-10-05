/* Browser regression for the local Today briefing and remediation simulation. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    await page.addInitScript(() => { Date.now = () => Date.parse('2026-10-02T12:00:00Z'); });
    const errors = [], posted = [], groupRequests = [];
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('request', (request) => { if (request.method() === 'POST') posted.push(request.url()); if (request.url().includes('group_evidence.json')) groupRequests.push(request.url()); });
    let changed = false, fail = false, rewind = false, groupFail = false;
    const date = '2026-10-02T10:00:00Z';
    const items = [1000, 2000, 3000].map((id, i) => ({ cve_id: `CVE-2026-${id}`, title: ['Gateway authentication bypass', 'Gateway service issue', 'Server vulnerability'][i],
      description: 'Test <img src=x onerror="window.injected=true">', exploitation_status: i === 0 ? 'known_exploited' : 'not_established', sources: ['cisa_kev', 'nvd'],
      reports: { cisa_kev: { vendor: 'Vendor', product: i < 2 ? 'Gateway' : 'Server', date_added: '2026-09-29', catalog_checked_at: date, required_action: 'Apply the vendor update.' },
        nvd: { severity: 'high', status: 'Analyzed', configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true,
          criteria: `cpe:2.3:a:vendor:${i < 2 ? 'gateway' : 'server'}:*:*:*:*:*:*:*:*`, versionEndExcluding: '2.0' }] }] }] } } }));
    await page.route('**/collections/vulnerabilities.json', (route) => fail ? route.fulfill({ status: 503, body: '{}' })
      : route.fulfill({ json: { schema_version: 1, generated_at: rewind ? '2026-09-29T00:00:00Z' : date, items } }));
    await page.route('**/group_evidence.json', (route) => groupFail ? route.fulfill({ status: 503, body: '{}' }) : route.fulfill({ json: { schema_version: 1, generated_at: date,
      groups: [{ name: 'alpha', ttps: ['T1190'] }, { name: 'beta', ttps: [] }], iocs: [],
      cves: [{ cve_id: 'CVE-2026-1000', groups: changed ? ['alpha', 'beta'] : ['alpha'], in_swiftioc: true },
        { cve_id: 'CVE-2026-9000', groups: ['alpha'], in_swiftioc: false }], evidence_history: { observations: {}, events: [] } } }));
    await page.goto(process.env.BASE_URL || 'http://127.0.0.1:8765');
    const today = page.locator('[data-today]');
    await today.locator('.today-card').first().waitFor();
    await page.waitForFunction(() => document.querySelector('[data-today-health]').textContent.includes('2 group-linked'));
    assert.match(await today.locator('[data-today-status]').innerText(), /not yet personalized/);
    assert.equal(groupRequests.length, 1, 'Today reuses the shared group snapshot request');
    await today.locator('.today-card').first().scrollIntoViewIfNeeded();
    const beforeReview = await page.evaluate(() => scrollY);
    await today.locator('.today-card').first().getByRole('button', { name: 'Review evidence' }).click();
    const drawer = page.locator('[data-vulnerability-drawer]');
    assert.equal(await drawer.isVisible(), true);
    assert.match(await drawer.locator('.today-evidence-profile').innerText(), /Independent corroboration.*not established/);
    assert.equal(await drawer.locator('img').count(), 0);
    if (process.env.SCREENSHOT_DIR) {
      await fs.mkdir(process.env.SCREENSHOT_DIR, { recursive: true });
      await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'today-evidence-desktop.png') });
    }
    await drawer.getByRole('button', { name: 'Close vulnerability details' }).click();
    assert.equal(await page.evaluate(() => location.hash), '', 'Closing the drawer returns to Today instead of changing sections');
    assert.ok(Math.abs((await page.evaluate(() => scrollY)) - beforeReview) < 100, 'Review keeps the reader near their briefing');
    await page.evaluate(() => {
      const state = { version: 1, watches: [{ vendor: 'Vendor', product: 'Gateway', ready: true }], records: {}, snapshotAt: null };
      localStorage.setItem('swiftioc-cve-briefing-v1', JSON.stringify(state));
      window.dispatchEvent(new CustomEvent('swiftioc:briefing-change', { detail: state }));
    });
    assert.equal(await today.locator('.today-card').count(), 2);
    assert.match(await today.locator('[data-today-status]').innerText(), /Personal briefing/);
    await today.locator('.today-card').first().getByRole('button', { name: 'Try patch scenario' }).click();
    assert.match(await today.locator('[data-today-plan-result]').innerText(), /No inventory loaded/);
    const inventory = { schema_version: 1, assets: [
      { id: 'private-edge', vendor: 'Vendor', product: 'Gateway', version: '1.0', cpe_vendor: 'vendor', cpe_product: 'gateway', exposure: 'internet', importance: 'critical' },
      { id: 'private-product-only', vendor: 'Vendor', product: 'Gateway' },
      { id: 'private-outside', vendor: 'Vendor', product: 'Gateway', version: '3.0', cpe_vendor: 'vendor', cpe_product: 'gateway' },
    ] };
    await page.locator('[data-inventory-file]').setInputFiles({ name: 'inventory.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(inventory)) });
    assert.match(await today.locator('[data-today-plan-result]').innerText(), /1 version-rule matches · 1 findings still need/);
    const download = page.waitForEvent('download');
    await today.getByRole('button', { name: 'Export scenario JSON (includes asset IDs)' }).click();
    const plan = JSON.parse(await fs.readFile(await (await download).path(), 'utf8'));
    assert.equal(plan.findings_before, 4); assert.equal(plan.findings_in_scenario, 2); assert.equal(plan.findings_remaining, 2);
    assert.deepEqual(plan.asset_ids, ['private-edge', 'private-product-only']);
    assert.equal(plan.groups[0].other_reported_cves, 1);
    assert.equal(Date.parse(plan.vulnerability_snapshot), Date.parse(date));
    assert.doesNotMatch(await page.evaluate(() => JSON.stringify(localStorage)), /private-edge|private-product-only|private-outside/);
    assert.equal(posted.some((url) => !url.includes('google-analytics') && !url.includes('googletagmanager')), false);
    if (process.env.SCREENSHOT_DIR) {
      await today.scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'today-desktop.png') });
      await today.locator('[data-today-planner]').scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'today-planner-desktop.png') });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await today.scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'today-mobile.png') });
    await page.locator('[data-inventory-clear]').evaluate((button) => button.click());
    assert.match(await today.locator('[data-today-plan-result]').innerText(), /No inventory loaded/);
    changed = true;
    await page.reload();
    await page.waitForFunction(() => document.querySelector('[data-today-status]').textContent.includes('1 changed'));
    assert.match(await today.locator('.today-card').first().innerText(), /Group associations changed/);
    const before = await page.evaluate(() => localStorage.getItem('swiftioc-cve-evidence-baseline-v2'));
    assert.ok(before);
    assert.equal(await page.evaluate(() => localStorage.getItem('swiftioc-today-baseline-v1')), null, 'Today does not duplicate the CVE baseline');
    rewind = true;
    await page.locator('[data-vulnerability-refresh]').evaluate((button) => button.click());
    await page.waitForFunction(() => document.querySelector('[data-today-status]').textContent.includes('older than'));
    assert.equal(await page.evaluate(() => localStorage.getItem('swiftioc-cve-evidence-baseline-v2')), before);
    fail = true;
    await page.locator('[data-vulnerability-refresh]').evaluate((button) => button.click());
    await page.waitForFunction(() => document.querySelector('[data-today-status]').textContent.includes('unavailable'));
    assert.equal(await today.locator('[data-today-plan-export]').isDisabled(), true);
    fail = false; rewind = false; groupFail = true;
    await page.reload();
    await page.waitForFunction(() => document.querySelector('[data-today-health]').textContent.includes('Group snapshot: unavailable'));
    assert.equal(await page.evaluate(() => localStorage.getItem('swiftioc-cve-evidence-baseline-v2')), before, 'Failed group load cannot erase baseline associations');
    groupFail = false;
    await page.evaluate(() => localStorage.removeItem('swiftioc-cve-briefing-v1'));
    await page.reload();
    await page.waitForFunction(() => document.querySelector('[data-today-status]').textContent.includes('0 changed'));
    assert.doesNotMatch(await today.locator('[data-today-status]').innerText(), /Personal briefing/);
    assert.deepEqual(errors, []);
    console.log('PASS: Today personalization, evidence provenance, what-if counts, private inventory, exports, material changes, snapshot rollback/failure, and mobile.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
