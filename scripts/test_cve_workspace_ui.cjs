/* Static-fixture browser checks. Run against public/ served on BASE_URL (default :8765). */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({ headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
    await page.addInitScript(() => { Date.now = () => Date.parse('2026-09-27T12:00:00Z'); });
    const errors = []; page.on('pageerror', (error) => errors.push(error.message));
    let changed = false;
    const items = Array.from({ length: 24 }, (_, i) => ({ cve_id: `CVE-2026-${1000 + i}`,
      title: i === 0 ? 'Gateway authentication bypass' : `Service security update ${i}`,
      description: 'Synthetic evidence <img src=x onerror="window.injected=true">',
      exploitation_status: i < 20 ? 'known_exploited' : 'not_established', sources: ['cisa_kev', 'nvd'],
      reports: { cisa_kev: { vendor: i % 2 ? 'Vendor Two' : 'Vendor One', product: 'Gateway', date_added: '2026-09-20',
        required_action: 'Install the vendor security update.', ransomware_use: 'Known', catalog_checked_at: '2026-09-27T00:00:00Z',
        reference: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' },
        nvd: { severity: i % 2 ? 'high' : 'critical', published_at: '2026-08-01T00:00:00Z', modified_at: '2026-09-26T00:00:00Z',
          status: 'Analyzed', reference: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1000' } },
    }));
    const groupData = () => ({ schema_version: 1, generated_at: '2026-09-27T00:00:00Z',
      groups: [{ name: 'alpha', ttps: ['T1190', 'T1486'], cves: [] }, { name: 'beta', ttps: ['T1190'], cves: [] }, { name: 'gamma', ttps: ['T1190'], cves: [] }], iocs: [],
      cves: [...items.map((item, i) => ({ cve_id: item.cve_id, groups: i === 0 ? (changed ? ['alpha', 'gamma'] : ['alpha', 'beta']) : ['alpha'], in_swiftioc: true })),
        { cve_id: 'CVE-2026-9999', groups: ['alpha', 'beta'], in_swiftioc: false }],
    });
    await page.route('**/collections/vulnerabilities.json', (route) => route.fulfill({ json: { schema_version: 1, generated_at: '2026-09-27T00:00:00Z', items } }));
    await page.route('**/group_evidence.json', (route) => route.fulfill({ json: groupData() }));
    await page.goto(process.env.BASE_URL || 'http://127.0.0.1:8765');
    const root = page.locator('#vulnerabilities');
    await root.locator('[data-vulnerability-status]').filter({ hasText: '20 of 24' }).waitFor();
    await root.locator('[data-vulnerability-view="group-linked"]').click();
    await root.locator('[data-vulnerability-status]').filter({ hasText: '25 group-linked' }).waitFor();
    assert.equal(await root.locator('.vulnerability-new-badge').count(), 0, 'First visit establishes a baseline');
    await root.locator('[data-vulnerability-layout="table"]').click();
    assert.equal(await root.locator('tbody tr').count(), 20);
    assert.match(await root.locator('thead').innerText(), /Severity/);
    await root.locator('tbody tr').first().getByRole('button', { name: 'Review', exact: true }).click();
    const drawer = root.locator('[data-vulnerability-drawer]');
    assert.equal(await drawer.isVisible(), true);
    assert.match(await drawer.innerText(), /Install the vendor security update/);
    assert.equal(await drawer.locator('img').count(), 0);
    await drawer.getByRole('button', { name: 'Mark reviewed', exact: true }).click();
    assert.match(await drawer.innerText(), /Current evidence reviewed/);
    await drawer.getByRole('button', { name: 'Next CVE' }).click();
    assert.match(await root.locator('[data-vulnerability-drawer-position]').innerText(), /2 of 25/);
    await drawer.getByRole('button', { name: 'Close vulnerability details' }).click();
    await root.locator('tbody input').first().check();
    await root.locator('[data-vulnerability-next]').click();
    await root.locator('tbody input').first().check();
    assert.match(await root.locator('[data-vulnerability-selected-count]').innerText(), /2 selected/);
    const download = page.waitForEvent('download');
    await root.locator('[data-vulnerability-export-selected]').click();
    const payload = JSON.parse(await fs.readFile(await (await download).path(), 'utf8'));
    assert.equal(payload.items.length, 2, 'Selection exports include earlier pages');
    assert.ok(payload.items.every((item) => item.group_snapshot && Array.isArray(item.timeline)));
    await root.locator('.vulnerability-tools-menu > summary').click();
    for (const format of ['csv', 'markdown', 'splunk']) {
      await root.locator('[data-vulnerability-export-format]').selectOption(format);
      const exported = page.waitForEvent('download');
      await root.locator('[data-vulnerability-export-selected]').click();
      const content = await fs.readFile(await (await exported).path(), 'utf8');
      assert.match(content, /CVE-2026-1000/);
      assert.match(content, /2026-09-27T00:00:00/);
      if (format === 'markdown') {
        assert.match(content, /&lt;img/);
        assert.doesNotMatch(content, /<img/);
      } else assert.match(content, /group_snapshot/);
    }
    await root.locator('[data-vulnerability-export-format]').selectOption('json');
    await root.locator('.vulnerability-tools-menu > summary').click();
    await root.locator('[data-vulnerability-clear-selected]').click();
    await root.locator('[data-vulnerability-search]').fill('CVE-2026-9999');
    assert.equal(await root.locator('tbody tr').count(), 1, 'Missing provider record remains reviewable');
    await root.getByRole('button', { name: 'Clear all', exact: true }).click();
    await root.locator('[data-vulnerability-view="group-linked"]').click();
    await root.locator('.vulnerability-analyst-tools > summary').click();
    await root.locator('[data-vulnerability-compare-a]').selectOption('alpha');
    await root.locator('[data-vulnerability-compare-b]').selectOption('beta');
    await root.getByRole('button', { name: 'Compare groups', exact: true }).click();
    assert.match(await root.locator('[data-vulnerability-compare-result]').innerText(), /2 shared CVEs/);
    await root.getByRole('button', { name: 'Show shared CVEs', exact: true }).click();
    assert.equal(await root.locator('tbody tr').count(), 2);
    await root.locator('.vulnerability-tools-menu > summary').click();
    page.once('dialog', (dialog) => dialog.accept('Shared group evidence'));
    await root.getByRole('button', { name: 'Save current view', exact: true }).click();
    await root.getByRole('button', { name: 'Clear all', exact: true }).click();
    await root.locator('[data-vulnerability-saved-views]').selectOption('0');
    assert.equal(await root.locator('tbody tr').count(), 2, 'Saved comparison restores the complete scope');
    await root.getByRole('button', { name: 'Clear all', exact: true }).click();
    await root.locator('.vulnerability-tools-menu > summary').click();
    await root.locator('[data-vulnerability-layout="cards"]').click();
    await root.locator('[data-vulnerability-search]').fill('CVE-2026-1000');
    assert.match(await root.locator('.vulnerability-card').innerText(), /Reviewed locally/);
    changed = true;
    await page.reload();
    await root.locator('[data-vulnerability-status]').filter({ hasText: '20 of 24' }).waitFor();
    await root.locator('[data-vulnerability-search]').fill('CVE-2026-1000');
    assert.match(await root.locator('.vulnerability-card').innerText(), /Changed since last visit/);
    assert.doesNotMatch(await root.locator('.vulnerability-card').innerText(), /Reviewed locally/);
    await root.locator('[data-vulnerability-search]').fill('');
    await root.locator('[data-vulnerability-view="group-linked"]').click();
    const focusRow = root.locator('.vulnerability-card').first();
    await focusRow.focus(); await page.keyboard.press('j'); await page.keyboard.press('Enter');
    assert.equal(await drawer.isVisible(), true);
    await page.keyboard.press('Escape');
    assert.equal(await drawer.isVisible(), false);
    assert.equal(await page.evaluate(() => window.injected), undefined);
    if (process.env.SCREENSHOT_DIR) {
      await fs.mkdir(process.env.SCREENSHOT_DIR, { recursive: true });
      await root.locator('[data-vulnerability-tiers]').scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'cve-workspace-desktop.png') });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await root.locator('[data-vulnerability-tiers]').scrollIntoViewIfNeeded();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, 'cve-workspace-mobile.png') });
    await root.locator('.vulnerability-card').first().getByRole('button', { name: 'Review details' }).click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('PASS: card/table, complete drawer, review invalidation, exact comparison, saved views, cross-page exports, keyboard, and mobile.');
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
