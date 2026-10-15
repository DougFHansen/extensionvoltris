/**
 * End-to-end verification against a real Chromium with the unpacked extension.
 *
 * Every hostile target is an RFC 2606 reserved name (`.test`) that never
 * resolves, and every legitimate page is served by a local fixture server. No
 * real malicious site is contacted at any point.
 */
import { expect, test } from '@playwright/test';
import {
  alarmNames,
  analyze,
  ExtensionHandle,
  FAKE_THREATS,
  FIXTURE_BASE,
  getRules,
  getSessionRules,
  getSettingsValue,
  getStorage,
  idleUntilSuspended,
  launchWithExtension,
  matchedRuleFeedAbsent,
  observedBlockedNavigations,
  recordedHistory,
  registeredListeners,
  seedThreats,
  sendMessage,
  setSettings,
} from './helpers';

const url = (h: ExtensionHandle, p: string) => h.url(p);

let handle: ExtensionHandle;

test.beforeAll(async () => {
  handle = await launchWithExtension();
});

test.afterAll(async () => {
  await handle?.context.close();
});

test.describe('extension loads', () => {
  test('the service worker starts and the manifest is valid', async () => {
    expect(handle.extensionId).toMatch(/^[a-p]{32}$/);
    const info = await sendMessage(handle, { v: 1, t: 'download.lists', p: {} }).then(() =>
      handle.withWorker((w) => w.evaluate(() => chrome.runtime.getManifest())),
    );
    expect(info.manifest_version).toBe(3);
    expect(info.name).toBeTruthy();
    expect(info.permissions).toContain('declarativeNetRequest');
    expect(info.permissions).toContain('alarms');
  });

  test('every listener registers - no capability dies silently', async () => {
    // A missing permission makes an API `undefined`; before defensive
    // registration that silently took down everything registered after it.
    expect(await registeredListeners(handle)).toEqual({
      onMessage: true,
      onInstalled: true,
      onStartup: true,
      onAlarm: true,
      onNavigationError: true,
      onDeterminingFilename: true,
      onTabsUpdated: true,
    });
  });

  test('runs with the unpacked-only matched-rule feed absent', async () => {
    // This is the production configuration. `declarativeNetRequestFeedback`
    // gates `onRuleMatchedDebug`, which Chrome documents as unpacked-only, so
    // a store install has neither. Everything below must therefore work with
    // the feed absent - which is exactly what this suite now exercises.
    expect(await matchedRuleFeedAbsent(handle)).toEqual({ permissionDeclared: false, apiPresent: false });
  });

  test('a periodic update alarm is scheduled', async () => {
    await expect.poll(async () => alarmNames(handle), { timeout: 20_000 }).toContain('vbs.feed-update');
  });

  test('the popup opens without errors', async () => {
    const page = await handle.context.newPage();
    const errors: string[] = [];
    page.on('console', (m) => {
      if (m.type() === 'error') errors.push(m.text());
    });
    page.on('pageerror', (e) => errors.push(String(e)));

    await page.goto(url(handle, 'popup.html'));
    await expect(page.locator('.popup-top')).toBeVisible();
    await expect(page.locator('.popup-stats')).toBeVisible();
    await expect(page.locator('.popup-brand')).toContainText('VOLTRIS');

    // No dishonest claim of absolute protection.
    const body = (await page.locator('body').innerText()).toLowerCase();
    expect(body).not.toContain('100% protected');
    expect(body).not.toContain('100% protegido');
    expect(errors).toEqual([]);
    await page.close();
  });

  test('the dashboard renders every section', async () => {
    const page = await handle.context.newPage();
    await page.goto(url(handle, 'dashboard.html'));
    await expect(page.locator('.page-nav')).toBeVisible();
    // Structural assertion: the tab count is language-independent.
    await expect(page.locator('.page-nav button')).toHaveCount(7);
    await page.locator('.page-nav button').nth(3).click();
    await expect(page.locator('.data-table-wrap, .empty').first()).toBeVisible();
    await page.close();
  });

  test('settings exposes eight tabs and persists a change', async () => {
    const page = await handle.context.newPage();
    await page.goto(url(handle, 'options.html'));
    await expect(page.locator('#settings-nav button')).toHaveCount(8);

    // Tab 1 is "web protection"; it owns the threat-category switches.
    await page.locator('#settings-nav button').first().click();
    const toggle = page.locator('#blockScam');
    await expect(toggle).toBeVisible();
    const before = await toggle.isChecked();
    await toggle.click();
    await expect.poll(async () => (await getSettingsValue(handle)).blockScam).toBe(!before);

    await page.reload();
    await page.locator('#settings-nav button').first().click();
    await expect(page.locator('#blockScam')).toBeChecked({ checked: !before });
    await page.close();
  });

  test('the interface renders in Brazilian Portuguese', async () => {
    const pt = await launchWithExtension({ lang: 'pt-BR' });
    try {
      const page = await pt.context.newPage();
      await page.goto(pt.url('popup.html'));
      await expect(page.locator('.popup-top')).toBeVisible();
      const text = await page.locator('body').innerText();
      // Translated, and not showing raw i18n message keys.
      expect(text).toMatch(/Prote|Amea|Rastread|Anuncios/i);
      expect(text).not.toMatch(/popup_|common_|reason_/);
      await page.close();
    } finally {
      await pt.context.close();
    }
  });
});

test.describe('threat intelligence', () => {
  test('a fictional malicious domain is really blocked by the browser', async () => {
    await setSettings(handle, { protectionEnabled: true, blockPhishing: true, blockMalware: true });
    await seedThreats(handle, [
      { domain: FAKE_THREATS.phishing, category: 'phishing' },
      { domain: FAKE_THREATS.malware, category: 'malware' },
    ]);

    const rules = await getRules(handle);
    const filters = rules.map((r) => r.condition.urlFilter);
    expect(filters).toContain(`||${FAKE_THREATS.phishing}^`);
    expect(filters).toContain(`||${FAKE_THREATS.malware}^`);

    // Real enforcement: the browser must refuse the navigation.
    const page = await handle.context.newPage();
    const failed: string[] = [];
    page.on('requestfailed', (r) => failed.push(r.url()));
    await page.goto(`http://${FAKE_THREATS.phishing}/`).catch(() => undefined);
    await page.waitForTimeout(1500);
    expect(
      failed.some((u) => u.includes(FAKE_THREATS.phishing)) || page.url().includes('blocked.html'),
      'navigation to a listed domain must not succeed',
    ).toBe(true);
    await page.close();
  });

  test('a clean page is not blocked', async () => {
    const page = await handle.context.newPage();
    await page.goto(`${FIXTURE_BASE}/clean.html`);
    await expect(page.locator('h1')).toHaveText('Legitimate banking page');
    await page.close();
  });

  test('the service worker survives idle suspension and resumes intact', async () => {
    // Chromium suspends an idle MV3 worker after ~30s. Everything in memory is
    // gone at that point; correctness depends entirely on what we persisted.
    //
    // (`chrome.runtime.reload()` is deliberately NOT used: on an unpacked
    // extension loaded via --load-extension it makes Chromium disable the
    // extension for the rest of the session.)
    await handle.closeProbe();
    const suspended = await idleUntilSuspended(handle, 45_000);

    // Whether or not the timer fired on this machine, the guarantee is the
    // same: the first interaction after the idle period must be fully correct.
    expect(await getStorage(handle, 'vbs.feedDataset')).not.toBeNull();
    expect((await analyze(handle, `http://${FAKE_THREATS.phishing}/`)).verdict).toBe('known-malicious');
    expect((await getRules(handle)).map((r) => r.condition.urlFilter)).toContain(`||${FAKE_THREATS.phishing}^`);

    // Reported for diagnostics; a machine that never suspends is not a failure.
    if (!suspended) {
      // eslint-disable-next-line no-console
      console.log('[note] the worker was never observed suspended within 45s on this machine');
    }
  });
});

test.describe('heuristics and false positives', () => {
  test('brand impersonation is suspicious, never malicious', async () => {
    const result = await analyze(handle, 'https://paypal.com.secure-login.test/');
    expect(result.verdict).toBe('suspicious');
    expect(result.categories).toHaveLength(0);
    expect(result.reasons.map((r) => r.code)).toContain('brand_impersonation_subdomain');
  });

  test('a legitimate page with a password field is not flagged', async () => {
    expect(['no-threat-found', 'not-analyzed']).toContain((await analyze(handle, `${FIXTURE_BASE}/banking.html`)).verdict);
  });

  test('missing HTTPS alone is never a finding', async () => {
    expect((await analyze(handle, 'http://plain-http-page.test/')).verdict).toBe('no-threat-found');
  });

  test('punycode alone is never a finding', async () => {
    expect((await analyze(handle, 'https://xn--e1afmkfd.xn--p1ai/')).verdict).toBe('no-threat-found');
  });

  test('many subdomains are never a finding', async () => {
    expect((await analyze(handle, 'https://a.b.c.d.e.f.example.test/')).verdict).toBe('no-threat-found');
  });

  test('the word "login" alone is never a finding', async () => {
    expect((await analyze(handle, 'https://login.example.test/')).verdict).toBe('no-threat-found');
  });

  test('an unparsable input is reported as not analysed, never as safe', async () => {
    expect((await analyze(handle, 'not a url')).verdict).toBe('not-analyzed');
  });
});

test.describe('allowlist', () => {
  test('an entry installs a scoped session rule and can be removed', async () => {
    expect((await getSessionRules(handle)).some((r) => r.condition.urlFilter === '||allow-me.test^')).toBe(false);

    await sendMessage(handle, { v: 1, t: 'allowlist.add', p: { domain: 'allow-me.test', scope: 'threats' } });

    const rule = (await getSessionRules(handle)).find((r) => r.condition.urlFilter === '||allow-me.test^');
    expect(rule).toBeDefined();
    // A "threats" exception must not allow navigating to the site itself.
    expect(rule!.condition.resourceTypes).not.toContain('main_frame');

    await sendMessage(handle, { v: 1, t: 'allowlist.remove', p: { domain: 'allow-me.test' } });
    expect((await getSessionRules(handle)).some((r) => r.condition.urlFilter === '||allow-me.test^')).toBe(false);
  });

  test('an allowlist entry is honoured by the analysis engine', async () => {
    await seedThreats(handle, [{ domain: 'allowed-threat.test', category: 'phishing' }]);
    await sendMessage(handle, { v: 1, t: 'allowlist.add', p: { domain: 'allowed-threat.test', scope: 'all' } });

    const result = await analyze(handle, 'http://allowed-threat.test/');
    // Facts do not change because a site was allowlisted; the exception is
    // surfaced separately and is what changes enforcement.
    expect(result.allowlisted).toBe(true);
    await sendMessage(handle, { v: 1, t: 'allowlist.remove', p: { domain: 'allowed-threat.test' } });
  });
});

test.describe('privacy', () => {
  test('typed passwords never reach extension storage', async () => {
    const page = await handle.context.newPage();
    await page.goto(`${FIXTURE_BASE}/clean.html`);
    await page.fill('input[name="password"]', 'SuperSecret123!');
    await page.waitForTimeout(1500);

    const dump = await handle.withWorker((w) => w.evaluate(async () => JSON.stringify(await chrome.storage.local.get(null))));
    expect(dump).not.toContain('SuperSecret123!');
    expect(dump).not.toContain('input[name');
    await page.close();
  });

  test('local data can be erased completely', async () => {
    await sendMessage(handle, {
      v: 1,
      t: 'data.clear',
      p: { settings: true, statistics: true, allowlist: true, history: true, threatData: true },
    });

    // The extension legitimately regenerates its own defaults so it can keep
    // working; what must be gone is everything the USER accumulated.
    const remaining = await handle.withWorker((w) =>
      w.evaluate(async () => Object.keys(await chrome.storage.local.get(null)).sort()),
    );
    expect(remaining.filter((k) => k.startsWith('vbs.') && k !== 'vbs.settings' && k !== 'vbs.stats')).toEqual([]);
    expect(remaining).toContain('vbs.settings');
    expect(remaining).toContain('vbs.stats');

    // And the regenerated state is a clean slate.
    const stats = await getStorage<Record<string, number>>(handle, 'vbs.stats');
    expect(stats?.blockedNavigations ?? 0).toBe(0);
    const history = await getStorage(handle, 'vbs.history');
    expect(history).toBeNull();
  });
});

test.describe('interstitial', () => {
  test('a blocked navigation shows an explanation and gates the bypass', async () => {
    await setSettings(handle, { protectionEnabled: true, blockPhishing: true });
    await seedThreats(handle, [{ domain: FAKE_THREATS.phishing, category: 'phishing' }]);

    const page = await handle.context.newPage();
    await page.goto(`http://${FAKE_THREATS.phishing}/`).catch(() => undefined);

    await page.waitForURL(/blocked\.html/, { timeout: 25_000 });
    await expect(page.locator('.blocked-card')).toBeVisible();
    await expect(page.locator('.blocked-head-text h1')).toBeVisible();
    await expect(page.locator('.blocked-target-text strong')).toContainText(FAKE_THREATS.phishing);

    // "Continue anyway" is disabled until the risk is acknowledged.
    const proceed = page.locator('.blocked-advanced button.btn-danger');
    await expect(proceed).toBeDisabled();
    await page.locator('#ack-risk').check();
    await expect(proceed).toBeEnabled();

    // A back button is always available.
    await expect(page.locator('.blocked-actions button').first()).toBeVisible();
    await page.close();
  });

  test('a blocked navigation is counted with the debug API unavailable', async () => {
    // REGRESSION TEST.
    //
    // The first build drove all statistics and this interstitial from
    // `declarativeNetRequest.onRuleMatchedDebug`. Chrome documents that event as
    // available only to unpacked extensions with the
    // `declarativeNetRequestFeedback` permission, so in a store install every
    // counter read zero AND the user got a raw browser error page.
    //
    // The extension no longer requests that permission, so this test runs in the
    // production configuration. If anyone reintroduces the debug feed, the
    // counting assertions below pass only in a dev build and the `apiPresent`
    // guard in "runs with the unpacked-only matched-rule feed absent" fails.
    const feed = await matchedRuleFeedAbsent(handle);
    expect(feed.apiPresent).toBe(false);

    await setSettings(handle, { protectionEnabled: true, blockPhishing: true });
    await seedThreats(handle, [{ domain: FAKE_THREATS.phishing, category: 'phishing' }]);

    const blockedBefore = await observedBlockedNavigations(handle);

    const page = await handle.context.newPage();
    await page.goto(`http://${FAKE_THREATS.phishing}/`).catch(() => undefined);
    await page.waitForURL(/blocked\.html/, { timeout: 25_000 });
    await page.close();

    // The counter must move on its own, from the observation the browser
    // reported. No polling, no inference from the rule count.
    await expect.poll(() => observedBlockedNavigations(handle), { timeout: 15_000 }).toBeGreaterThan(blockedBefore);

    // And the event is attributed to the feed that actually listed the domain,
    // not to a rule id from an API that does not exist in production.
    const blocked = (await recordedHistory(handle)).find((e) => e.kind === 'threat_blocked');
    expect(blocked, 'no threat_blocked event was recorded').toBeTruthy();
    expect(blocked?.providerId).toBeTruthy();
    expect(blocked?.providerId).not.toMatch(/^rule:/);
  });

  test('a block we did not cause is not claimed as ours', async () => {
    // `net::ERR_BLOCKED_BY_CLIENT` also fires when ANOTHER extension blocks a
    // request. Counting those would inflate our numbers with someone else's
    // work, and showing our interstitial for a URL absent from our dataset
    // would be a false accusation.
    await setSettings(handle, { protectionEnabled: true, blockPhishing: true });
    await seedThreats(handle, [{ domain: FAKE_THREATS.phishing, category: 'phishing' }]);

    const blockedBefore = await observedBlockedNavigations(handle);

    // A plain DNS failure: not a client-side block, and not in our dataset.
    const page = await handle.context.newPage();
    await page.goto('http://this-host-does-not-exist.invalid/').catch(() => undefined);
    await page.waitForTimeout(2_000);
    expect(page.url()).not.toMatch(/blocked\.html/);
    await page.close();

    expect(await observedBlockedNavigations(handle)).toBe(blockedBefore);
  });

  test('the dashboard discloses which metrics cannot be measured', async () => {
    // An unmeasurable metric must be labelled, not silently shown as zero. A
    // user who sees an absent row cannot distinguish "we cannot measure this"
    // from "we forgot to measure this".
    const page = await handle.context.newPage();
    await page.goto(url(handle, 'dashboard.html'));
    await expect(page.locator('.metric-list')).toBeVisible();

    const rows = page.locator('.metric-row');
    await expect(rows).toHaveCount(5);
    // Exactly one metric is declared unavailable, and it says so on its own row.
    await expect(page.locator('.metric-row.is-unavailable')).toHaveCount(1);
    await expect(page.locator('.metric-row.is-unavailable .metric-state')).toBeVisible();

    const text = await page.locator('.metric-list').innerText();
    expect(text.toLowerCase()).toContain('not measurable');
    await page.close();
  });
});

test.describe('responsiveness', () => {
  test('surfaces render at a narrow viewport without horizontal overflow', async () => {
    const page = await handle.context.newPage();
    await page.setViewportSize({ width: 380, height: 560 });
    for (const surface of ['popup.html', 'dashboard.html', 'options.html']) {
      await page.goto(url(handle, surface));
      await page.waitForTimeout(600);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, `${surface} overflows horizontally at 380px`).toBeLessThanOrEqual(1);
    }
    await page.close();
  });

  test('the theme follows the system preference', async () => {
    const page = await handle.context.newPage();
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.goto(url(handle, 'dashboard.html'));
    await expect.poll(async () => page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    await page.close();
  });
});
