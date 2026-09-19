const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto(process.env.BASE_URL || 'http://127.0.0.1:8765');
    await page.locator('.analyst-guide > summary').click();
    const input = page.locator('[data-investigation-import]');
    const status = page.locator('[data-investigation-import-status]');
    const saved = () => page.evaluate(() => JSON.parse(localStorage.getItem('swiftioc-investigation-workspace-v1') || '[]'));
    const upload = async content => {
      await input.setInputFiles({ name: 'queue.json', mimeType: 'application/json', buffer: Buffer.from(content) });
      await page.waitForFunction(() => !document.querySelector('[data-investigation-import]').disabled);
    };
    const rows = [{ indicator: '1[.]2[.]3[.]4', type: 'ipv4', tags: ['test'] }, { indicator: 'CVE-2026-1234', type: 'cve' }];
    await upload(JSON.stringify(rows));
    assert.match(await status.innerText(), /2 indicators imported/);
    assert.equal((await saved()).length, 2);
    assert.match(await page.locator('[data-investigation-spl-code]').textContent(), /1\.2\.3\.4/);
    const downloadEvent = page.waitForEvent('download');
    await page.locator('[data-investigation-json]').click();
    const download = await downloadEvent;
    let exported = ''; for await (const chunk of await download.createReadStream()) exported += chunk.toString();
    await upload(exported);
    assert.match(await status.innerText(), /0 indicators imported; 2 duplicates/);
    // Duplicate-only import must not destroy Undo for the original import.
    await page.locator('[data-workspace-undo]').click();
    assert.deepEqual(await saved(), []);
    await upload(exported);
    assert.deepEqual(await saved(), JSON.parse(exported));
    const baseline = await saved();
    for (const content of ['{broken', JSON.stringify([...rows, { indicator: 42, type: 'ipv4' }]), ' '.repeat(500001)]) {
      await upload(content);
      assert.equal(await status.evaluate(el => el.classList.contains('hunt-error')), true);
      assert.deepEqual(await saved(), baseline);
    }
    const extra = Array.from({ length: 49 }, (_, i) => ({ indicator: `host${i}.test`, type: 'domain' }));
    await upload(JSON.stringify(extra));
    assert.match(await status.innerText(), /51 of 50/);
    assert.deepEqual(await saved(), baseline);
    await upload(JSON.stringify([{ indicator: 'hxxps://host/Payload', type: 'url' }, { indicator: 'hxxps://host/payload', type: 'url' }]));
    assert.equal((await saved()).length, 4);
    await page.locator('[data-workspace-undo]').click();
    assert.deepEqual(await saved(), baseline);
    await page.locator('.analyst-guide').scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: '/tmp/investigation-import-mobile.png' });
    await page.reload();
    assert.deepEqual(await saved(), baseline);
    assert.equal(await page.locator('[data-workspace-undo]').isVisible(), false);
    await page.locator('.analyst-guide > summary').click();
    await page.evaluate(() => {
      const original = Storage.prototype.setItem;
      Storage.prototype.setItem = function (key, value) {
        if (key === 'swiftioc-investigation-workspace-v1') throw new Error('Simulated storage failure');
        return original.call(this, key, value);
      };
    });
    await upload(JSON.stringify([{ indicator: 'new.test', type: 'domain' }]));
    assert.match(await status.innerText(), /Browser save failed/);
    assert.equal(await page.locator('[data-investigation-count]').innerText(), '3');
    assert.deepEqual(await saved(), baseline);
    assert.deepEqual(errors, []);
    console.log('Investigation import: round-trip, duplicate Undo, validation, capacity, URL case, persistence and mobile layout passed.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
