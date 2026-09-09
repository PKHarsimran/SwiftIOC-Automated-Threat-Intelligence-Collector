const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    const errors = []; page.on('pageerror', (error) => errors.push(error.message));
    let failure = false;
    const generated = new Date(Date.now() - 60000).toISOString();
    await page.route('**/collections/vulnerabilities.json', (route) => route.fulfill({ status: failure ? 503 : 200,
      contentType: 'application/json', body: JSON.stringify({ schema_version: 1, generated_at: generated, items: [{
        cve_id: 'CVE-2026-1234', sources: ['cisa_kev'], exploitation_status: 'known_exploited', reports: {
          cisa_kev: { vendor: 'Vendor', product: 'Server', required_action: 'Update' },
          nvd: { configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true,
            criteria: 'cpe:2.3:a:vendor:server:*:*:*:*:*:*:*:*', versionEndExcluding: '3.0' }] }] }] },
        },
      }] }) }));
    await page.goto(process.env.BASE_URL || 'http://127.0.0.1:8765');
    await page.locator('[data-vulnerability-status]').filter({ hasText: '1 of 1 CVEs' }).waitFor();
    await page.locator('[data-inventory-root] > summary').click();
    const assets = [{ id: '<img src=x onerror=alert(1)>', vendor: 'Vendor', product: 'Server', version: '2.5', cpe_vendor: 'vendor', cpe_product: 'server', exposure: 'internet', importance: 'critical' }];
    const upload = (value) => page.locator('[data-inventory-file]').setInputFiles({ name: 'inventory.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
    await upload({ schema_version: 1, assets });
    await page.locator('[data-inventory-status]').filter({ hasText: '1 findings' }).waitFor();
    assert.match(await page.locator('[data-inventory-results]').innerText(), /version match/);
    assert.equal(await page.locator('[data-inventory-results] img').count(), 0);
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-inventory-export]').click()]);
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'inventory-test-'));
    try {
      const file = path.join(dir, 'report.json'); await download.saveAs(file);
      const report = JSON.parse(await fs.readFile(file, 'utf8'));
      assert.equal(report.findings[0].status, 'version-match');
      assert.equal(report.snapshot_generated_at, generated);
    } finally { await fs.rm(dir, { recursive: true }); }
    await upload({ schema_version: 1, assets: [assets[0], assets[0]] });
    await page.locator('[data-inventory-status]').filter({ hasText: 'Import rejected' }).waitFor();
    assert.equal(await page.locator('[data-inventory-export]').isDisabled(), false);
    failure = true; await page.locator('[data-vulnerability-refresh]').click();
    await page.locator('[data-vulnerability-status]').filter({ hasText: 'Collection unavailable' }).waitFor();
    assert.equal(await page.locator('[data-inventory-export]').isDisabled(), true);
    assert.equal(await page.locator('[data-inventory-results] article').count(), 0);
    failure = false; await page.locator('[data-vulnerability-refresh]').click();
    await page.locator('[data-inventory-status]').filter({ hasText: '1 findings' }).waitFor();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (process.env.SCREENSHOT_DIR) {
      await page.locator('[data-inventory-root]').scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${process.env.SCREENSHOT_DIR}/inventory-mobile.png` });
    }
    for (const generated_at of ['2000-01-01T00:00:00Z', '2999-01-01T00:00:00Z']) {
      await page.evaluate((generated_at) => window.dispatchEvent(new CustomEvent('swiftioc:vulnerability-snapshot', { detail: { items: [], generated_at } })), generated_at);
      assert.equal(await page.locator('[data-inventory-export]').isDisabled(), true);
      assert.equal(await page.locator('[data-inventory-results] article').count(), 0);
    }
    await page.locator('[data-inventory-clear]').click();
    assert.equal(await page.locator('[data-inventory-export]').isDisabled(), true);
    await upload({ schema_version: 1, assets });
    await page.reload();
    await page.locator('[data-inventory-root] > summary').click();
    await page.locator('[data-inventory-status]').filter({ hasText: 'Import an inventory' }).waitFor();
    assert.match(await page.locator('[data-inventory-status]').innerText(), /Import an inventory/);
    assert.deepEqual(errors, []);
    console.log('PASS: inventory import, safe rendering, evidence export, invalid replacement, refresh failure/retry, mobile layout, clear, and tab-only lifetime.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
