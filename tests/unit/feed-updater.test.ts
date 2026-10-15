/**
 * Feed update engine: data-only fetching, validation, atomic swap, downgrade
 * protection and tamper resistance.
 *
 * `fetch` is fully injected, so NOTHING in this file touches the network.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FeedError, fetchFeed, parseProviderFeed, updateFeeds } from '../../src/feeds/updater';
import { FEED_REGISTRY, providerById } from '../../src/feeds/registry';
import type { ProviderDescriptor } from '../../src/core/types';

// ---------------------------------------------------------------- chrome shim

const store = new Map<string, unknown>();
const area = {
  get: async (keys: null) => Object.fromEntries(store),
  set: async (items: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(items)) store.set(k, v);
  },
  remove: async (keys: string | string[]) => {
    for (const key of Array.isArray(keys) ? keys : [keys]) store.delete(key);
  },
  clear: async () => store.clear(),
};
(globalThis as Record<string, unknown>).chrome = { storage: { local: area, session: area } };

const { invalidateReputationCache } = await import('../../src/security/reputation');

function provider(id: string): ProviderDescriptor {
  const found = providerById(id);
  if (!found) throw new Error(`missing provider ${id}`);
  return found;
}

function textResponse(body: string, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  return new Response(body, { status: init.status ?? 200, headers: init.headers ?? {} });
}

beforeEach(() => {
  store.clear();
  invalidateReputationCache();
  vi.restoreAllMocks();
});

// ------------------------------------------------------------------- registry

describe('provider registry integrity', () => {
  it('has unique provider ids', () => {
    const ids = FEED_REGISTRY.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('uses https for every feed URL', () => {
    for (const p of FEED_REGISTRY) {
      expect(new URL(p.feedUrl).protocol, p.id).toBe('https:');
    }
  });

  it('records a licence decision for every provider', () => {
    for (const p of FEED_REGISTRY) {
      expect(typeof p.license.commercialUseAllowed, p.id).toBe('boolean');
      expect(p.license.url.length, p.id).toBeGreaterThan(0);
      if (!p.license.commercialUseAllowed) {
        expect(p.excludedFromProduct, `${p.id} must be excluded when commercial use is not allowed`).toBe(true);
        expect(p.exclusionReason, `${p.id} must explain the exclusion`).toBeTruthy();
      }
    }
  });

  it('marks every excluded provider as NOT fetchable', () => {
    for (const p of FEED_REGISTRY.filter((x) => x.excludedFromProduct)) {
      expect(['excluded_license', 'not_configured']).toContain(p.requiresCredential ? 'not_configured' : 'excluded_license');
      if (!p.requiresCredential) expect(p.exclusionReason).toBeTruthy();
    }
  });

  it('excludes OpenPhish for non-commercial terms', () => {
    const openphish = providerById('openphish');
    expect(openphish?.excludedFromProduct).toBe(true);
    expect(openphish?.license.commercialUseAllowed).toBe(false);
  });

  it('keeps URLhaus disabled until a key is configured', () => {
    const urlhaus = providerById('urlhaus');
    expect(urlhaus?.requiresCredential).toBe(true);
    expect(urlhaus?.excludedFromProduct).toBe(true);
  });
});

// ---------------------------------------------------------------- fetch guard

describe('fetchFeed guards', () => {
  it('refuses an excluded provider before any request', async () => {
    const spy = vi.fn();
    await expect(fetchFeed(provider('openphish'), { fetchImpl: spy as never })).rejects.toBeInstanceOf(FeedError);
    expect(spy).not.toHaveBeenCalled();
  });

  it('refuses a provider that needs a credential', async () => {
    const spy = vi.fn();
    await expect(fetchFeed(provider('urlhaus'), { fetchImpl: spy as never })).rejects.toMatchObject({ code: 'excluded' });

    await expect(
      fetchFeed(provider('phishtank'), { fetchImpl: spy as never }),
    ).rejects.toMatchObject({ code: 'not_configured' });
    expect(spy).not.toHaveBeenCalled();
  });

  it('sends no cookies when fetching', async () => {
    let seen: RequestInit | undefined;
    const spy = vi.fn(async (_url: string, init?: RequestInit) => {
      seen = init;
      return textResponse('a.test\n');
    });
    await fetchFeed(provider('phishing-database-domains'), { fetchImpl: spy as never });
    expect(seen?.credentials).toBe('omit');
  });
});

// ------------------------------------------------------------- payload guard

describe('parseProviderFeed validation', () => {
  it('accepts a well-formed domain list', () => {
    const parsed = parseProviderFeed(provider('phishing-database-domains'), '# c\na.test\nb.test\n');
    expect(parsed.domains.size).toBe(2);
  });

  it('rejects an empty or error-page payload', () => {
    expect(() => parseProviderFeed(provider('phishing-database-domains'), '')).toThrow(/valid entries/);
    expect(() => parseProviderFeed(provider('phishing-database-domains'), '<html>404</html>')).toThrow();
  });

  it('rejects a payload that is only invalid hostnames', () => {
    expect(() => parseProviderFeed(provider('phishing-database-domains'), '!!!\n???\n<<<')).toThrow();
  });

  it('never throws on binary garbage', () => {
    const garbage = String.fromCharCode(...Array.from({ length: 5000 }, (_, i) => i % 256));
    expect(() => parseProviderFeed(provider('phishing-database-domains'), garbage)).toThrow();
  });

  it('extracts the feed day for provenance', () => {
    const parsed = parseProviderFeed(provider('phishing-database-domains'), '# Date: 20261010\na.test\n');
    expect(parsed.feedVersion).toBe('20261010');
  });
});

// --------------------------------------------------------------- update cycle

describe('updateFeeds atomicity and downgrade protection', () => {
  const goodPhishing = '# Date: 20261013\nmalicious-a.test\nmalicious-b.test\n';
  const goodPhishingLinks = 'https://malicious-link.test/login\n';
  const goodBlack = '0.0.0.0 bad-c.test\n0.0.0.0 bad-d.test\n';

  function fakeFetch(bodies: Record<string, string>): typeof fetch {
    return (async (url: string) => {
      const match = Object.entries(bodies).find(([fragment]) => String(url).includes(fragment));
      if (!match) return textResponse('', { status: 404 });
      return textResponse(match[1]);
    }) as unknown as typeof fetch;
  }

  /**
   * Every credential-free provider succeeds.
   *
   * The link feed is keyed on `phishing-links-ACTIVE`, NOT `...-ACTIVE-today`:
   * the upstream `-today` file exists but is served EMPTY (verified 2026-10-15,
   * HTTP 200 with 0 bytes), which made this provider fail on every real run.
   * The fixture matches the URL the registry actually requests.
   */
  function allGoodFetch(): typeof fetch {
    return fakeFetch({
      'phishing-domains-ACTIVE': goodPhishing,
      'phishing-links-ACTIVE': goodPhishingLinks,
      'StevenBlack/hosts': goodBlack,
      'easylist': '||ads.test^\n',
      'easyprivacy': '||tracker.test^\n',
    });
  }

  it('never requests the empty upstream link file', () => {
    // Guards the regression directly: if the registry points at the file the
    // publisher leaves empty, every install loses this provider silently.
    const linkProvider = FEED_REGISTRY.find((p) => p.id === 'phishing-database-links');
    expect(linkProvider, 'link provider missing from the registry').toBeTruthy();
    expect(linkProvider!.feedUrl).not.toContain('ACTIVE-today');
  });

  it('writes a new dataset and increments the revision', async () => {
    const outcome = await updateFeeds({ force: true, fetchImpl: allGoodFetch() });
    expect(outcome.ok).toBe(true);
    expect(outcome.revision).toBe(1);
    expect(outcome.previousDatasetPreserved).toBe(false);
    expect(outcome.updated.find((s) => s.id === 'phishing-database-domains')?.entryCount).toBe(2);
    // A full-URL feed contributes only its host; paths are never stored.
    expect(outcome.updated.find((s) => s.id === 'phishing-database-links')?.entryCount).toBe(1);
  });

  it('persists the last attempt time so the throttle survives a restart', async () => {
    await updateFeeds({ force: true, fetchImpl: allGoodFetch() });
    const state = store.get('vbs.feedState') as { lastAttemptAt: number };
    expect(typeof state.lastAttemptAt).toBe('number');
    expect(state.lastAttemptAt).toBeGreaterThan(0);
  });

  it('preserves the previous valid dataset when every provider fails', async () => {
    const first = await updateFeeds({ force: true, fetchImpl: allGoodFetch() });
    expect(first.revision).toBe(1);

    const second = await updateFeeds({ force: true, fetchImpl: fakeFetch({}) });
    expect(second.ok).toBe(false);
    expect(second.previousDatasetPreserved).toBe(true);
    // The last good dataset is still there, marked stale but usable.
    const stored = store.get('vbs.feedDataset') as { revision: number; states: { id: string; status: string; entryCount: number }[] };
    expect(stored.revision).toBe(1);
    const phishing = stored.states.find((s) => s.id === 'phishing-database-domains');
    expect(phishing!.entryCount).toBe(2);
  });

  it('keeps a good provider when another provider fails', async () => {
    const outcome = await updateFeeds({
      force: true,
      fetchImpl: fakeFetch({ 'phishing-domains-ACTIVE': goodPhishing }),
    });
    const phishing = outcome.updated.find((s) => s.id === 'phishing-database-domains');
    const black = outcome.updated.find((s) => s.id === 'stevenblack-hosts');
    expect(phishing!.status).toBe('active');
    expect(phishing!.entryCount).toBe(2);
    expect(black!.status).toBe('error');
  });

  it('never decreases the revision', async () => {
    await updateFeeds({ force: true, fetchImpl: fakeFetch({ 'phishing-domains-ACTIVE': goodPhishing }) });
    const before = (store.get('vbs.feedDataset') as { revision: number }).revision;
    const after = await updateFeeds({ force: true, fetchImpl: fakeFetch({ 'phishing-domains-ACTIVE': '# Date: 20200101\nold.test\n' }) });
    expect(after.revision).toBeGreaterThan(before);
  });

  it('records a SHA-256 of the validated payload', async () => {
    const outcome = await updateFeeds({
      force: true,
      fetchImpl: fakeFetch({ 'phishing-domains-ACTIVE': goodPhishing }),
    });
    const hash = outcome.updated.find((s) => s.id === 'phishing-database-domains')?.contentHash;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('reports excluded and unconfigured providers instead of pretending they work', async () => {
    const outcome = await updateFeeds({ force: true, fetchImpl: fakeFetch({}) });
    const openphish = outcome.updated.find((s) => s.id === 'openphish');
    const urlhaus = outcome.updated.find((s) => s.id === 'urlhaus');
    const phishtank = outcome.updated.find((s) => s.id === 'phishtank');
    expect(openphish!.status).toBe('excluded_license');
    expect(urlhaus!.status).toBe('excluded_license');
    expect(phishtank!.status).toBe('not_configured');
  });

  it('respects the minimum interval unless forced', async () => {
    await updateFeeds({ force: true, fetchImpl: fakeFetch({ 'phishing-domains-ACTIVE': goodPhishing }) });
    const revision = (store.get('vbs.feedDataset') as { revision: number }).revision;

    const spy = vi.fn(fakeFetch({ 'phishing-domains-ACTIVE': 'other.test\n' }));
    const throttled = await updateFeeds({ fetchImpl: spy as never });
    expect(throttled.revision).toBe(revision);
    expect(spy).not.toHaveBeenCalled();
  });

  it('honours the only= filter', async () => {
    const outcome = await updateFeeds({
      force: true,
      only: ['phishing-database-domains'],
      fetchImpl: fakeFetch({ 'phishing-domains-ACTIVE': goodPhishing }),
    });
    expect(outcome.updated.find((s) => s.id === 'phishing-database-domains')?.status).toBe('active');
    expect(outcome.updated.find((s) => s.id === 'stevenblack-hosts')?.status).not.toBe('active');
  });

  it('exposes conversion counters so nothing is silently dropped', async () => {
    const outcome = await updateFeeds({
      force: true,
      fetchImpl: fakeFetch({ easylist: '||a.test^\n##.cosmetic\n/regex/\n||b.test^$popup\n' }),
    });
    const easy = outcome.updated.find((s) => s.id === 'easylist');
    expect(easy!.entryCount).toBe(1);
    expect(easy!.skipped).toBeGreaterThan(0);
    expect(easy!.skippedByReason.regex_filter).toBe(1);
    expect(easy!.skippedByReason.cosmetic_filter).toBe(1);
    expect(easy!.skippedByReason.unsupported_option).toBe(1);
  });
});
