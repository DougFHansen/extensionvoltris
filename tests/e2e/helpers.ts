/**
 * Shared helpers for the end-to-end suite.
 *
 * Locates the extension that Playwright loaded, gives tests a typed bridge to
 * the service worker, and provides a way to seed a fictional threat list so
 * blocking can be verified WITHOUT ever visiting a real malicious site.
 *
 * IMPORTANT: a Manifest V3 service worker is suspended aggressively by the
 * browser. A cached Playwright `Worker` reference therefore goes stale after a
 * few idle seconds, and every helper here goes through `withWorker()`, which
 * transparently revives the worker and retries once.
 *
 * `chrome` is a GLOBAL inside the service-worker realm, so evaluated functions
 * reference it directly instead of receiving it as an argument.
 */
import { chromium, type BrowserContext, type Worker } from '@playwright/test';
import { join } from 'node:path';

export const FIXTURE_BASE = 'http://127.0.0.1:4319';

/** Reserved, RFC 2606 names used as fictional threats. `.test` never resolves. */
export const FAKE_THREATS = {
  phishing: 'phishing-login.test',
  malware: 'malware-drop.test',
  tracker: 'tracker-cdn.test',
} as const;

function isStaleWorkerError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /Could not establish connection|Target closed|Worker was destroyed|Execution context was destroyed|has been closed/i.test(
    message,
  );
}

/** Polls until a live service worker shows up. Does not need the extension id. */
async function waitForAnyWorker(context: BrowserContext, timeout = 45_000): Promise<Worker> {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const candidate of context.serviceWorkers()) {
      try {
        await candidate.evaluate(() => 1);
        return candidate;
      } catch {
        // Suspended or destroyed; try the next one.
      }
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('no live extension service worker appeared');
}

export class ExtensionHandle {
  /** Reused page used as a first-party message channel. */
  private probe: import('@playwright/test').Page | null = null;

  constructor(
    readonly context: BrowserContext,
    readonly extensionId: string,
  ) {}

  url(path: string): string {
    return `chrome-extension://${this.extensionId}/${path}`;
  }

  /**
   * Returns a live worker, reviving a suspended one if necessary.
   *
   * A suspended MV3 worker still answers `evaluate` (that is what revives it);
   * a DESTROYED one throws, which is the case we must recover from.
   */
  async ensureWorker(timeout = 30_000): Promise<Worker> {
    for (const candidate of this.context.serviceWorkers()) {
      try {
        await candidate.evaluate(() => 1);
        return candidate;
      } catch {
        // stale
      }
    }

    // Opening an extension page revives a suspended worker.
    const page = await this.context.newPage();
    try {
      await page.goto(this.url('popup.html'), { waitUntil: 'domcontentloaded' }).catch(() => undefined);
    } finally {
      await page.close().catch(() => undefined);
    }
    return waitForAnyWorker(this.context, timeout);
  }

  /** Runs `fn` against a live worker, retrying once if the worker was asleep. */
  async withWorker<T>(fn: (worker: Worker) => Promise<T>): Promise<T> {
    const worker = await this.ensureWorker();
    try {
      return await fn(worker);
    } catch (error) {
      if (!isStaleWorkerError(error)) throw error;
      return fn(await this.ensureWorker());
    }
  }

  /**
   * Sends a protocol message the way the real interface does: from an
   * EXTENSION PAGE to the service worker.
   *
   * A service worker cannot message its own `onMessage` listener, so messages
   * must originate in a page context. Using a real page also means these tests
   * exercise the same code path a user does.
   */
  async send<T = unknown>(message: Record<string, unknown>): Promise<T> {
    await this.ensureWorker();
    if (!this.probe || this.probe.isClosed()) {
      const page = await this.context.newPage();
      await page.goto(this.url('popup.html'), { waitUntil: 'domcontentloaded' });
      this.probe = page;
    }
    return this.probe.evaluate(async (m) => chrome.runtime.sendMessage(m as never), message) as Promise<T>;
  }

  async closeProbe(): Promise<void> {
    if (this.probe && !this.probe.isClosed()) await this.probe.close().catch(() => undefined);
    this.probe = null;
  }
}

export async function launchWithExtension(options: { lang?: string } = {}): Promise<ExtensionHandle> {
  const lang = options.lang ?? 'en-US';
  const userDataDir = join(process.env.TEMP ?? '.', `vbs-e2e-${process.pid}-${lang}`);
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    headless: true,
    args: [
      `--disable-extensions-except=${process.cwd()}/dist/chrome`,
      `--load-extension=${process.cwd()}/dist/chrome`,
      `--lang=${lang}`,
      `--accept-lang=${lang}`,
      '--no-sandbox',
      '--disable-gpu',
      '--no-first-run',
      '--disable-features=DialMediaRouteProvider,OptimizationHints',
    ],
  });

  const worker = await waitForAnyWorker(context);
  return new ExtensionHandle(context, new URL(worker.url()).host);
}

export interface AnalysisView {
  verdict: string;
  categories: string[];
  reasons: { code: string }[];
  allowlisted: boolean;
  score: number;
  hostname: string | null;
  registrableDomain: string | null;
}

/**
 * Seeds a fictional threat feed directly into extension storage, then triggers a
 * rule rebuild through the SAME code path a user action uses.
 *
 * Nothing bypasses the real pipeline: dataset -> reputation index -> compiled
 * DNR rules -> browser enforcement -> matched-rule feedback.
 */
export async function seedThreats(handle: ExtensionHandle, entries: { domain: string; category: string }[]): Promise<void> {
  await handle.withWorker(async (worker) => {
    await worker.evaluate(async (list) => {
      const now = Date.now();

      const buckets: Record<string, string[]> = {
        'phishing-database-domains': [],
        'stevenblack-hosts': [],
        easyprivacy: [],
      };
      for (const entry of list) {
        const bucket =
          entry.category === 'phishing'
            ? 'phishing-database-domains'
            : entry.category === 'tracker'
              ? 'easyprivacy'
              : 'stevenblack-hosts';
        buckets[bucket]!.push(entry.domain);
      }

      const states = (Object.keys(buckets) as (keyof typeof buckets)[]).map((id) => ({
        id,
        status: 'active',
        lastSuccessAt: now,
        lastAttemptAt: now,
        lastError: null,
        entryCount: buckets[id]!.length,
        ruleCount: 0,
        contentHash: null,
        feedVersion: null,
        skipped: 0,
        skippedByReason: {},
      }));

      const dataset: Record<string, unknown> = {
        schemaVersion: 1,
        revision: (Date.now() % 100_000) + 1,
        updatedAt: now,
        states,
      };
      const reputation: Record<string, unknown> = {};
      for (const [id, domains] of Object.entries(buckets)) {
        const packed = domains.sort().join('\n');
        dataset[id] = packed;
        reputation[`vbs.threats.${id}`] = packed;
      }

      await chrome.storage.local.set({
        'vbs.feedDataset': dataset,
        'vbs.threats.__meta': states,
        ...reputation,
      });
    }, entries);

    // A settings patch is the same rebuild path a user action triggers.
    await handle.send({ v: 1, t: 'settings.patch', p: { blockPhishing: true } });
  });

  await new Promise((r) => setTimeout(r, 400));
}

export async function getRules(handle: ExtensionHandle) {
  return handle.withWorker((worker) => worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules()));
}

export async function getSessionRules(handle: ExtensionHandle) {
  return handle.withWorker((worker) => worker.evaluate(() => chrome.declarativeNetRequest.getSessionRules()));
}

/** Which listener groups actually registered. Proves no capability died silently. */
export async function registeredListeners(handle: ExtensionHandle) {
  return handle.withWorker((worker) =>
    worker.evaluate(() => ({
      onMessage: chrome.runtime.onMessage.hasListeners(),
      onInstalled: chrome.runtime.onInstalled.hasListeners(),
      onStartup: chrome.runtime.onStartup.hasListeners(),
      onAlarm: chrome.alarms.onAlarm.hasListeners(),
      // The production block observer. Not the unpacked-only matched-rule feed.
      onNavigationError: chrome.webNavigation.onErrorOccurred.hasListeners(),
      onDeterminingFilename: chrome.downloads.onDeterminingFilename.hasListeners(),
      onTabsUpdated: chrome.tabs.onUpdated.hasListeners(),
    })),
  );
}

/**
 * Confirms the unpacked-only matched-rule feed is genuinely absent.
 *
 * The shipped manifest no longer requests `declarativeNetRequestFeedback`, so
 * a published extension has no such API. Asserting it here means the tests are
 * exercising the same configuration a store install gets, rather than a
 * development-only superset.
 */
export async function matchedRuleFeedAbsent(handle: ExtensionHandle) {
  return handle.withWorker((worker) =>
    worker.evaluate(() => ({
      permissionDeclared: chrome.runtime.getManifest().permissions?.includes('declarativeNetRequestFeedback') ?? false,
      apiPresent: typeof (chrome.declarativeNetRequest as { onRuleMatchedDebug?: unknown }).onRuleMatchedDebug !== 'undefined',
    })),
  );
}

export async function alarmNames(handle: ExtensionHandle): Promise<string[]> {
  return handle.withWorker(async (worker) => (await worker.evaluate(() => chrome.alarms.getAll())).map((a) => a.name));
}

export async function getStorage<T = Record<string, unknown>>(handle: ExtensionHandle, key: string): Promise<T | null> {
  return handle.withWorker((worker) =>
    worker.evaluate(async (k) => {
      const result = await chrome.storage.local.get(k);
      return (result[k] as never) ?? null;
    }, key),
  );
}

export async function setSettings(handle: ExtensionHandle, patch: Record<string, unknown>): Promise<void> {
  await handle.send({ v: 1, t: 'settings.patch', p: patch });
}

export async function getSettingsValue(handle: ExtensionHandle): Promise<Record<string, boolean>> {
  return (await getStorage<Record<string, boolean>>(handle, 'vbs.settings')) ?? {};
}

export async function sendMessage<T = unknown>(handle: ExtensionHandle, message: Record<string, unknown>): Promise<T> {
  return handle.send<T>(message);
}

export async function analyze(handle: ExtensionHandle, url: string): Promise<AnalysisView> {
  return sendMessage<{ ok: boolean; data?: { result: AnalysisView } }>(handle, { v: 1, t: 'get.analysis', p: { url } }).then(
    (response) => response.data!.result,
  );
}

/** Shape of `get.status` as far as the statistics assertions need it. */
interface StatusView {
  ok: boolean;
  data?: { stats: { blockedNavigations: number; blockedNavigationsByCategory: Record<string, number> } };
}

/**
 * Observed blocked-navigation count, read from the service worker.
 *
 * This is the number the user sees. Reading it through the same message the
 * dashboard uses means a test failure points at a real UI defect rather than at
 * a difference between the test's view and the product's.
 */
export async function observedBlockedNavigations(handle: ExtensionHandle): Promise<number> {
  const response = await sendMessage<StatusView>(handle, { v: 1, t: 'get.status', p: {} });
  return response.ok ? (response.data?.stats.blockedNavigations ?? 0) : 0;
}

/** Recorded security events, newest first. */
export async function recordedHistory(handle: ExtensionHandle): Promise<{ kind: string; providerId?: string; category?: string }[]> {
  const response = await sendMessage<{ ok: boolean; data?: { history: { kind: string; providerId?: string; category?: string }[] } }>(
    handle,
    { v: 1, t: 'get.dashboard', p: {} },
  );
  return response.ok ? (response.data?.history ?? []) : [];
}

/**
 * Waits for the MV3 service worker to be suspended by the browser.
 *
 * NOTE: `chrome.runtime.reload()` is NOT usable here. On an unpacked extension
 * loaded via `--load-extension`, a reload causes Chromium to disable the
 * extension for the rest of the browser session (`ERR_BLOCKED_BY_CLIENT`), so
 * it cannot be used to simulate a worker restart. Genuine idle suspension is the
 * property that actually matters, and this exercises it.
 */
export async function idleUntilSuspended(handle: ExtensionHandle, idleMs = 40_000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < idleMs) {
    const live = await context_hasLiveWorker(handle);
    if (!live) return true;
    await new Promise((r) => setTimeout(r, 2_000));
  }
  return false;
}

async function context_hasLiveWorker(handle: ExtensionHandle): Promise<boolean> {
  for (const candidate of handle.context.serviceWorkers()) {
    try {
      await candidate.evaluate(() => 1);
      return true;
    } catch {
      // destroyed
    }
  }
  return handle.context.serviceWorkers().length > 0;
}

/** True when the browser currently reports no running service worker. */
export async function workerIsSuspended(handle: ExtensionHandle): Promise<boolean> {
  return (await context_hasLiveWorker(handle)) === false;
}
