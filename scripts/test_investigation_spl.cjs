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
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.evaluate(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'instant' }));
    const originalScroll = await page.evaluate(() => scrollY);
    assert.equal(await page.locator('[data-workspace-dock-count]').innerText(), '2');
    await page.locator('[data-workspace-open]').click();
    assert.ok(await page.evaluate(() => scrollY) < originalScroll);
    await page.locator('[data-workspace-return]').click();
    assert.ok(Math.abs(await page.evaluate(() => scrollY) - originalScroll) < 2);
    await page.evaluate(() => {
      const root = document.querySelector('[data-investigation-root]');
      window.scrollTo({ top: root.offsetTop + 100, behavior: 'instant' });
    });
    const partialScroll = await page.evaluate(() => scrollY);
    await page.locator('[data-workspace-open]').click();
    assert.equal(await page.locator('[data-workspace-return]').isVisible(), true);
    await page.locator('[data-workspace-open]').click();
    await page.locator('[data-workspace-return]').click();
    assert.ok(Math.abs(await page.evaluate(() => scrollY) - partialScroll) < 2);
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
    await page.locator('[data-spl-index]').fill('security-prod');
    await page.locator('[data-spl-time]').selectOption('-1h');
    await page.locator('.hunt-mappings summary').click();
    await page.locator('[data-spl-field="src_ip"]').fill('source.ip');
    const configured = await page.locator('[data-investigation-spl-code]').textContent();
    assert.ok(configured.startsWith('index=security-prod earliest=-1h'));
    assert.ok(configured.includes("'source.ip'"));
    await page.locator('[data-investigation-spl-copy]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), configured.trim());
    await page.locator('[data-spl-index]').fill('main | delete');
    assert.equal(await page.locator('[data-investigation-spl-copy]').isDisabled(), true);
    assert.equal(await page.locator('[data-investigation-spl-download]').isDisabled(), true);
    assert.ok(!(await page.locator('[data-investigation-spl-code]').textContent()).includes('cidrmatch'));
    await page.locator('[data-spl-index]').fill('security-prod');
    assert.equal(await page.locator('[data-investigation-spl-copy]').isDisabled(), false);
    await page.locator('[data-investigation-root]').screenshot({ path: '/tmp/hunt-desktop.png', style: '.site-nav, .toast, .skip-link { visibility: hidden !important; }' });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('[data-investigation-root]').screenshot({ path: '/tmp/hunt-mobile.png', style: '.site-nav, .toast, .skip-link { visibility: hidden !important; }' });
    await page.locator('[data-spl-reset]').click();
    assert.equal(await page.locator('[data-spl-index]').inputValue(), 'YOUR_INDEX');
    assert.equal(await page.locator('[data-spl-field="src_ip"]').inputValue(), 'src_ip');
    await page.locator('[data-spl-index]').fill('retain_this');

    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    await page.getByRole('button', { name: 'Remove 1[.]2[.]3[.]4 from investigation queue', exact: true }).click();
    assert.equal(await page.locator('[data-investigation-spl-copy]').isDisabled(), true);
    assert.equal(await page.locator('[data-investigation-spl-download]').isDisabled(), true);
    assert.ok(!(await page.locator('[data-investigation-spl-code]').textContent()).includes('1.2.3.4'));
    assert.equal(await page.locator('[data-spl-index]').inputValue(), 'retain_this');
    assert.equal(await page.locator('[data-workspace-dock-count]').innerText(), '1');
    assert.equal(await page.evaluate(() => document.activeElement?.getAttribute('aria-label')), 'Remove CVE-2026-1234 from investigation queue');
    await page.setViewportSize({ width: 320, height: 640 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    const dockBounds = await page.locator('[data-workspace-dock]').boundingBox();
    assert.ok(dockBounds.x >= 0 && dockBounds.x + dockBounds.width <= 320);

    await page.getByRole('button', { name: 'Remove CVE-2026-1234 from investigation queue', exact: true }).click();
    assert.equal(await page.locator('[data-workspace-dock]').isHidden(), true);
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'ioc-lookup-input');
    assert.deepEqual(errors, []);
    console.log('PASS: queued SPL, copy/download contents, skipped types, stale-query removal, mobile layout.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
