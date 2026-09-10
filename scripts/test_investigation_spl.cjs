const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
  try {
    const context = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
    await context.addInitScript(() => localStorage.setItem('swiftioc-investigation-workspace-v1', JSON.stringify([
      { indicator: '1[.]2[.]3[.]4', type: 'ipv4' }, { indicator: 'CVE-2026-1234', type: 'cve' },
    ])));
    const page = await context.newPage(); const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await page.goto(process.env.BASE_URL || 'http://127.0.0.1:8765');
    await page.locator('[data-investigation-spl-copy]').click();
    const code = await page.locator('[data-investigation-spl-code]').textContent();
    assert.ok(code.includes('cidrmatch("1.2.3.4/32"'));
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), code.trim());
    assert.match(await page.locator('[data-investigation-spl-status]').innerText(), /1 unsupported/);
    const downloadPromise = page.waitForEvent('download');
    await page.locator('[data-investigation-spl-download]').click();
    const download = await downloadPromise;
    assert.equal(download.suggestedFilename(), 'swiftioc-selected-iocs.spl');
    const stream = await download.createReadStream();
    let downloaded = ''; for await (const chunk of stream) downloaded += chunk.toString();
    assert.equal(downloaded, code);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.getByRole('button', { name: 'Remove 1[.]2[.]3[.]4 from investigation queue', exact: true }).click();
    assert.equal(await page.locator('[data-investigation-spl-copy]').isDisabled(), true);
    assert.equal(await page.locator('[data-investigation-spl-download]').isDisabled(), true);
    assert.ok(!(await page.locator('[data-investigation-spl-code]').textContent()).includes('1.2.3.4'));
    assert.deepEqual(errors, []);
    console.log('PASS: queued SPL, copy/download contents, skipped types, stale-query removal, mobile layout.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
