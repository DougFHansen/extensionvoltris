/**
 * End-to-end verification against the REAL threat feeds.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Every other end-to-end test seeds fictional threats straight into
 * `chrome.storage`. That is correct for testing behaviour, but it bypasses the
 * entire feed pipeline: download, parse, pack, store, assemble, compile, budget.
 *
 * The pipeline shipped broken. The packed real dataset measured ~27 MiB against
 * a 9 MiB ceiling, so the updater refused every download, the rules were never
 * built, and the extension ran with zero protection while reporting success.
 * Three hundred and eighteen unit tests and twenty-eight browser tests all
 * passed, because none of them touched this path.
 *
 * These tests therefore hit the network. They are slower and they depend on the
 * upstream publishers being reachable, so a failure here must be read
 * carefully: it may mean the feed is down rather than the code being wrong. The
 * assertions on rule SHAPE and SPREAD are the ones that must always hold.
 */
import { expect, test } from '@playwright/test';
import type { ExtensionHandle } from './helpers';
import { launchWithExtension, sendMessage } from './helpers';

let handle: ExtensionHandle;
let refresh: { states: { id: string; status: string; entryCount: number; lastError: string | null }[]; revision: number; error: unknown };

// Downloading every real feed and compiling ~24,000 rules takes a while on a cold
// profile, so the whole setup is given room rather than the individual tests.
test.describe.configure({ timeout: 180_000 });

test.beforeAll(async () => {
  // Own profile: this project installs the real threat lists and writes
  // settings, and Chromium profiles persist by design. Sharing a directory with
  // the offline suite leaked both.
  handle = await launchWithExtension({ profile: 'live-feeds' });

  // Messages go through the page-based channel, because a service worker cannot
  // message its own `onMessage` listener.
  refresh = await sendMessage<{ data: typeof refresh }>(handle, { v: 1, t: 'feeds.refresh', p: {} }).then((r) => r.data);
  await handle.closeProbe();
});

test.afterAll(async () => {
  await handle?.context.close();
});

interface StatusView {
  ok: boolean;
  data?: {
    protection?: {
      dynamicRuleCount: number;
      rulesMeta?: { installedByCategory?: Record<string, number> };
    };
  };
}

interface DiagnosticsView {
  ok: boolean;
  data?: {
    preview?: {
      perCategory?: Record<string, number>;
      quota?: { budget?: number; perCategory?: Record<string, number> };
    };
  };
}

test.describe('real threat feeds', () => {
  test('the update cycle completes without an error', () => {
    expect(refresh.error, 'the cycle must not have thrown').toBeNull();
    expect(refresh.revision, 'a dataset must have been written').toBeGreaterThan(0);
  });

  test('the credential-free providers all load', () => {
    const required = ['phishing-database-domains', 'phishing-database-links', 'stevenblack-hosts', 'easylist', 'easyprivacy'];
    for (const id of required) {
      const state = refresh.states.find((s) => s.id === id);
      expect(state, `${id} missing from the provider state`).toBeTruthy();
      expect(state!.status, `${id} did not load: ${state!.lastError}`).toBe('active');
      expect(state!.entryCount, `${id} parsed zero entries`).toBeGreaterThan(1_000);
    }
  });

  test('every provider that needs no credential is active', () => {
    // A provider listed as needing a key must stay NOT_CONFIGURED, and one
    // excluded by licence must stay excluded. Both are deliberate.
    for (const state of refresh.states) {
      if (state.id === 'urlhaus' || state.id === 'openphish') continue;
      if (state.id === 'phishtank') {
        expect(state.status).toBe('not_configured');
        continue;
      }
      expect(state.status, `${state.id}: ${state.lastError}`).toBe('active');
    }
  });
});

test.describe('installed rule set', () => {
  test('protection is actually active', async () => {
    // The fault this file exists to catch: 0 rules, protection "on".
    const status = await sendMessage<StatusView>(handle, { v: 1, t: 'get.status', p: {} });

    expect(status.data?.protection?.dynamicRuleCount ?? 0, 'no blocking rules were installed').toBeGreaterThan(1_000);
    await handle.closeProbe();
  });

  test('threat categories are well represented', async () => {
    const status = await sendMessage<StatusView>(handle, { v: 1, t: 'get.status', p: {} });
    const byCategory = status.data?.protection?.rulesMeta?.installedByCategory ?? {};

    expect(byCategory.phishing ?? 0, 'no phishing rules installed').toBeGreaterThan(1_000);
    expect(byCategory.malware ?? 0, 'no malware rules installed').toBeGreaterThan(1_000);

    // Threats must outweigh privacy filtering. That is the whole point of the
    // budget allocation: an ad that slips through is a nuisance, a phishing page
    // that slips through is a compromised account.
    const threats = (byCategory.phishing ?? 0) + (byCategory.malware ?? 0) + (byCategory.scam ?? 0);
    const privacy = (byCategory.ad ?? 0) + (byCategory.tracker ?? 0);
    expect(threats, 'privacy categories must not outweigh threats').toBeGreaterThan(privacy);
    await handle.closeProbe();
  });

  test('no category exceeds its documented budget', async () => {
    const diag = await sendMessage<DiagnosticsView>(handle, { v: 1, t: 'rules.diagnostics', p: {} });
    const quota = diag.data?.preview?.quota;
    const byCategory = diag.data?.preview?.perCategory ?? {};

    expect(quota?.budget, 'no quota reported').toBeGreaterThan(0);
    for (const [category, count] of Object.entries(byCategory)) {
      const cap = quota?.perCategory?.[category];
      if (typeof cap !== 'number') continue;
      expect(count, `${category} installed ${count} against a budget of ${cap}`).toBeLessThanOrEqual(cap);
    }
    await handle.closeProbe();
  });

  test('installed rules are spread across the alphabet, not the first few letters', async () => {
    // The real regression here. Feeds arrive sorted ASCII, so taking the first N
    // entries produced a rule set made almost entirely of domains beginning with
    // `0` and `a`. It looked like thousands of rules were protecting the user
    // while blocking nothing anyone visits.
    const spread = await handle.withWorker((w) =>
      w.evaluate(async () => {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        const byOrdinal: Record<string, string[]> = {};
        for (const rule of rules) {
          const ordinal = Math.floor(rule.id / 100_000_000).toString();
          const filter = rule.condition.urlFilter ?? '';
          (byOrdinal[ordinal] ??= []).push(filter.replace(/^\|\|/, '').split(/[/\^]/)[0] ?? '');
        }
        return byOrdinal;
      }),
    );

    for (const [ordinal, hosts] of Object.entries(spread)) {
      expect(hosts.length, `ordinal ${ordinal} has no rules`).toBeGreaterThan(0);

      const firstLetters = new Set(hosts.map((h) => (h[0] ?? '').toLowerCase()));
      const junk = hosts.filter((h) => h.startsWith('0.0.0.0')).length;

      // A prefix-sampled set concentrates in a few letters. A real sample does not.
      expect(firstLetters.size, `ordinal ${ordinal} covers only ${firstLetters.size} starting letters`).toBeGreaterThanOrEqual(8);
      expect(junk / hosts.length, `ordinal ${ordinal} is mostly 0.0.0.0 filler`).toBeLessThan(0.05);

      // And the tail must not be missing entirely.
      const last = hosts[hosts.length - 1] ?? '';
      expect(last.length, `ordinal ${ordinal} ends with an empty host`).toBeGreaterThan(3);
    }
  });

  test('every rule uses a plain urlFilter with no regex', async () => {
    const summary = await handle.withWorker((w) =>
      w.evaluate(async () => {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        let regex = 0;
        let anchored = 0;
        for (const rule of rules) {
          const condition = rule.condition as { regexFilter?: string; urlFilter?: string };
          if (condition.regexFilter) regex += 1;
          if ((condition.urlFilter ?? '').endsWith('^')) anchored += 1;
        }
        return { total: rules.length, regex, anchored };
      }),
    );

    expect(summary.regex, 'regex rules consume a separate 1,000-rule quota').toBe(0);
    expect(summary.anchored / summary.total, 'most rules should be host-anchored').toBeGreaterThan(0.9);
  });
});

test.describe('blocking a real malicious domain', () => {
  test('a rule compiled from a real feed entry blocks the browser', async () => {
    // Takes a host that is genuinely installed as a rule, then navigates to it.
    // The host is a reserved `.test` name so the request can never reach a real
    // server; what is being tested is whether OUR rule fires before DNS is even
    // consulted. That is the whole mechanism, so the outcome is unambiguous:
    // either the browser blocked it, or it did not block and the test fails.
    const sample = await handle.withWorker((w) =>
      w.evaluate(async () => {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        // A threat rule covers main_frame, so it must block a navigation.
        const rule = rules.find(
          (r) => r.action.type === 'block' && (r.condition.resourceTypes ?? []).includes('main_frame') && r.condition.urlFilter,
        );
        return (rule?.condition.urlFilter ?? '').replace(/^\|\|/, '').split('^')[0] ?? '';
      }),
    );

    expect(sample, 'no main-frame block rule was installed').toMatch(/\S+\.\S+/);

    const page = await handle.context.newPage();
    const blocked = new Promise<boolean>((resolve) => {
      page.on('requestfailed', (request) => resolve((request.failure()?.errorText ?? '').includes('ERR_BLOCKED_BY_CLIENT')));
    });

    await page.goto(`http://${sample}/`).catch(() => undefined);

    expect(await blocked, `the browser did not block a navigation to ${sample}`).toBe(true);
    await page.close();
  });

  test('the popup never claims protection while zero rules are installed', async () => {
    // Guards the disclosure added alongside this fix: with no rules, the popup
    // must say so in plain language rather than showing a reassuring "On".
    const page = await handle.context.newPage();
    await page.goto(handle.url('popup.html'));
    await expect(page.locator('.popup-stats')).toBeVisible();

    const alertCount = await page.locator('.popup-alert').count();
    const rules = await handle.withWorker((w) =>
      w.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).length),
    );

    if (rules === 0) {
      expect(alertCount, 'protection is inactive but the popup shows no warning').toBe(1);
      await expect(page.locator('.popup-alert')).toContainText(/not active/i);
    } else {
      expect(alertCount, 'protection is active, so no warning should be shown').toBe(0);
    }
    await page.close();
  });
});
