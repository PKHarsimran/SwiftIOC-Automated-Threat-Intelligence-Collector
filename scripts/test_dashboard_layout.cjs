/* Serve public/ locally. Uses synthetic indicators and Playwright + Chromium.
 * BASE_URL defaults to http://127.0.0.1:8765.
 */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}),
  });
  const base = process.env.BASE_URL || 'http://127.0.0.1:8765';
  try {
    const context = await browser.newContext({ reducedMotion: 'reduce', viewport: { width: 1440, height: 1000 } });
    const feed = Array.from({ length: 30 }, (_, i) => JSON.stringify({
      indicator: `192.0.2.${i + 1}`, type: 'ipv4', score: 90, confidence: 'high',
      source: 'fixture-a,fixture-b', tags: 'fixture-shared', last_seen: new Date().toISOString(),
    })).join('\n');
    await context.route('**/iocs/dashboard.jsonl', (route) => route.fulfill({ contentType: 'application/x-ndjson', body: feed }));
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(base, { waitUntil: 'networkidle' });
    const rows = page.locator('[data-preview-body] > tr:not(.preview-detail-row)');
    assert.equal(await rows.count(), 12);
    assert.equal(await page.locator('[data-tool-disclosure][open]').count(), 0);
    // Native summary controls must work with the keyboard.
    const exports = page.locator('details').filter({ has: page.locator('#exports') });
    const summary = exports.locator(':scope > summary');
    await summary.focus();
    await page.keyboard.press('Enter');
    assert.equal(await exports.getAttribute('open'), '');
    await page.keyboard.press('Enter');
    assert.equal(await exports.getAttribute('open'), null);
    await page.locator('.nav-links a[href="#exports"]').click();
    await page.waitForFunction(() => document.getElementById('exports').closest('details').open);
    await exports.evaluate((element) => { element.open = false; });
    await page.locator('.nav-links a[href="#exports"]').click();
    await page.waitForFunction(() => document.getElementById('exports').closest('details').open);
    // Existing direct links must reveal ancestors on initial navigation.
    for (const id of ['sources', 'tags', 'indicator-types', 'campaign-graph']) {
      await page.goto(`${base}/#${id}`, { waitUntil: 'networkidle' });
      assert.equal(await page.locator(`#${id}`).evaluate((element) => element.closest('details').open), true);
    }
    await page.locator('[data-graph-node]').first().click();
    assert.equal(await page.locator('[data-graph-node][aria-pressed="true"]').count(), 1);
    await page.locator('[data-campaign-graph]').click({ position: { x: 4, y: 4 } });
    assert.equal(await page.locator('[data-graph-node][aria-pressed="true"]').count(), 0);
    assert.equal(await page.locator('.campaign-edge.is-dimmed').count(), 0);
    await page.locator('[data-graph-node]').first().click();
    assert.equal(await page.locator('[data-graph-node][aria-pressed="true"]').count(), 1);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('[data-graph-node][aria-pressed="true"]').count(), 0);
    // Malformed fragments cannot break bootstrap or expose a selector error.
    await page.goto(`${base}/#%E0%A4%A`, { waitUntil: 'networkidle' });
    assert.equal(await rows.count(), 12);
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(base, { waitUntil: 'networkidle' });
    assert.equal(await rows.count(), 6);
    assert.equal(await page.locator('[data-preview-limit]').inputValue(), '6');
    await page.locator('[data-preview-limit]').selectOption('12');
    await page.reload({ waitUntil: 'networkidle' });
    assert.equal(await rows.count(), 12);
    await page.locator('[data-preview-limit]').selectOption('6');
    await page.reload({ waitUntil: 'networkidle' });
    assert.equal(await rows.count(), 6);
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `Page overflow at ${width}px`);
      const links = await page.locator('.nav-links a').evaluateAll((elements) => elements.map((el) => {
        const rect = el.getBoundingClientRect();
        return { left: rect.left, right: rect.right, height: rect.height };
      }));
      for (const link of links) {
        assert.ok(link.left >= 0 && link.right <= width, `Navigation clipped at ${width}px`);
        assert.ok(link.height >= 44, 'Navigation touch target too short');
      }
    }
    await page.locator('.analyst-guide > summary').click();
    await page.locator('.analyst-guide a[href="#product-briefing"]').click();
    await page.waitForFunction(() => document.querySelector('[data-briefing-settings]').open);
    assert.equal(await page.locator('[data-briefing-settings]').getAttribute('open'), '');
    await page.locator('[data-briefing-settings]').evaluate(el => { el.open = false; });
    await page.locator('.analyst-guide a[href="#product-briefing"]').click();
    await page.waitForFunction(() => document.querySelector('[data-briefing-settings]').open);
    assert.equal(await page.locator('[data-briefing-settings]').getAttribute('open'), '');
    assert.deepEqual(errors, []);
    // Downloads remain available if dashboard JavaScript fails or is disabled.
    const noJs = await browser.newPage({ javaScriptEnabled: false });
    await noJs.goto(base);
    const downloadSummary = noJs.locator('.tool-disclosure > summary').filter({ hasText: 'Downloads & integrations' });
    await downloadSummary.click();
    assert.equal(await noJs.locator('#exports a').first().isVisible(), true);
    console.log('PASS: keyboard disclosures, bookmarks, repeated anchors, graph selection, compact/shared rows, mobile navigation, and no-JS downloads.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
