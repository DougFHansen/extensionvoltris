/**
 * Local storage, statistics and history.
 *
 * The acceptance criteria require that every displayed number corresponds to a
 * real observable event, that history never becomes a browsing-history
 * surrogate, and that local data can be erased completely.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const store = new Map<string, unknown>();
const sessionStore = new Map<string, unknown>();
const listeners: ((changes: Record<string, unknown>, area: string) => void)[] = [];

function makeArea(backing: Map<string, unknown>) {
  return {
    get: async (keys: unknown) => {
      if (keys === null) return Object.fromEntries(backing);
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const key of list) if (backing.has(key)) out[key] = backing.get(key);
      return out;
    },
    set: async (items: Record<string, unknown>) => {
      const changes: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(items)) {
        changes[k] = { oldValue: backing.get(k), newValue: v };
        backing.set(k, v);
      }
      for (const l of listeners) l(changes, 'local');
    },
    remove: async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) backing.delete(key);
    },
    clear: async () => backing.clear(),
  };
}

const area = makeArea(store);

(globalThis as Record<string, unknown>).chrome = {
  storage: {
    local: area,
    session: makeArea(sessionStore),
    onChanged: { addListener: (l: never) => listeners.push(l), removeListener: () => undefined },
  },
  alarms: { clear: async () => undefined, create: () => undefined },
};

const {
  getStats,
  recordBlockedNavigation,
  recordSuspiciousDetection,
  recordDownload,
  flushStats,
  resetStats,
  invalidateStatsCache,
  dailySeries,
} = await import('../../src/data/stats');
const { recordHistory, getHistory, clearHistory, summarize, invalidateHistoryCache } = await import('../../src/data/history');
const { clearData, usage, byteSizeOf } = await import('../../src/platform/storage');
const { getSettings, updateSettings, resetSettings, invalidateSettingsCache } = await import('../../src/data/settings');
const { DEFAULT_SETTINGS } = await import('../../src/core/types');
const { addToAllowlist, getAllowlist, removeFromAllowlist, setEntryScope, setEntryEnabled, clearAllowlist, invalidateAllowlistCache, toAllowlistDomain } =
  await import('../../src/data/allowlist');

beforeEach(() => {
  store.clear();
  sessionStore.clear();
  listeners.length = 0;
  invalidateStatsCache();
  invalidateHistoryCache();
  invalidateSettingsCache();
  invalidateAllowlistCache();
  vi.useRealTimers();
});

describe('statistics reflect observed events only', () => {
  it('counts a blocked phishing navigation once, under its category', async () => {
    recordBlockedNavigation({ category: 'phishing', domain: 'evil.test', at: Date.now() });
    await flushStats();
    const stats = await getStats();
    expect(stats.blockedNavigations).toBe(1);
    expect(stats.blockedNavigationsByCategory.phishing).toBe(1);
    expect(stats.blockedNavigationsByCategory.malware).toBeUndefined();
  });

  it('keeps malware_distribution separate from the malware tally', async () => {
    recordBlockedNavigation({ category: 'malware_distribution', domain: 'dl.example.test', at: Date.now() });
    await flushStats();
    const stats = await getStats();
    expect(stats.blockedNavigations).toBe(1);
    expect(stats.blockedNavigationsByCategory.malware_distribution).toBe(1);
    expect(stats.blockedNavigationsByCategory.malware).toBeUndefined();
  });

  it('does not lose counts when events arrive back to back', async () => {
    // The observer fires several times in quick succession. Concurrent updates
    // that each read the same base snapshot would silently drop the extras.
    for (let i = 0; i < 25; i += 1) {
      recordBlockedNavigation({ category: 'phishing', domain: `e${i}.evil.test`, at: Date.now() });
    }
    await flushStats();
    expect((await getStats()).blockedNavigations).toBe(25);
  });

  it('starts at zero and never invents numbers', async () => {
    const stats = await getStats();
    expect(stats.blockedNavigations).toBe(0);
    expect(stats.blockedNavigationsByCategory).toEqual({});
    expect(stats.blockedByDay).toEqual({});
    expect(stats.topBlockedDomains).toEqual({});
  });

  it('caps the top-domains table', async () => {
    for (let i = 0; i < 80; i += 1) {
      recordBlockedNavigation({ category: 'phishing', domain: `d${i}.example.test`, at: Date.now() });
    }
    await flushStats();
    const stats = await getStats();
    expect(Object.keys(stats.topBlockedDomains).length).toBeLessThanOrEqual(50);
    expect(stats.blockedNavigations).toBe(80);
  });

  it('ignores a null domain instead of writing a bogus entry', async () => {
    recordBlockedNavigation({ category: 'scam', domain: null, at: Date.now() });
    await flushStats();
    const stats = await getStats();
    expect(stats.blockedNavigations).toBe(1);
    expect(stats.topBlockedDomains).toEqual({});
  });

  it('builds a dense daily series', async () => {
    const series = dailySeries(await getStats(), 14);
    expect(series).toHaveLength(14);
    expect(series.every((p) => /^\d{4}-\d{2}-\d{2}$/.test(p.day))).toBe(true);
  });

  it('survives a corrupted stored value', async () => {
    store.set('vbs.stats', 'not-an-object');
    invalidateStatsCache();
    await expect(getStats()).resolves.toBeTruthy();
  });

  it('discards counters from the pre-1.1 schema rather than reinterpreting them', async () => {
    // The old per-category fields meant per-REQUEST matches produced by an API
    // that does not exist in a published build. Carrying them onto the new
    // fields would import numbers we can no longer vouch for, and the user
    // would read them as blocks we actually observed.
    store.set('vbs.stats', { threatsBlocked: 412, phishingBlocked: 400, trackersBlocked: 12, adsBlocked: 9, updatedAt: 1 });
    invalidateStatsCache();
    const stats = await getStats();
    expect(stats.blockedNavigations).toBe(0);
    expect(stats.blockedNavigationsByCategory).toEqual({});
    expect(stats.blockedByDay).toEqual({});
    expect(stats.topBlockedDomains).toEqual({});
  });

  it('resets cleanly', async () => {
    recordBlockedNavigation({ category: 'phishing', domain: 'x.test', at: Date.now() });
    await flushStats();
    await resetStats();
    const stats = await getStats();
    expect(stats.blockedNavigations).toBe(0);
    expect(stats.blockedNavigationsByCategory).toEqual({});
  });
});

describe('history privacy', () => {
  it('stores only the domain by default', async () => {
    await recordHistory({ kind: 'threat_blocked', domain: 'evil.test', storeFullUrls: false, url: 'https://evil.test/secret/path?token=abc' });
    const [event] = await getHistory();
    expect(event!.domain).toBe('evil.test');
    expect(event!.url).toBeUndefined();
  });

  it('strips the query string even when full URLs are enabled', async () => {
    await recordHistory({
      kind: 'threat_blocked',
      domain: 'evil.test',
      storeFullUrls: true,
      url: 'https://evil.test/secret/path?token=abc#frag',
    });
    const [event] = await getHistory();
    expect(event!.url).toBe('https://evil.test/secret/path');
  });

  it('enforces the ring-buffer cap', async () => {
    for (let i = 0; i < 400; i += 1) {
      await recordHistory({ kind: 'ad_blocked', domain: `d${i}.test`, storeFullUrls: false });
    }
    const history = await getHistory();
    expect(history.length).toBeLessThanOrEqual(300);
  });

  it('newest event first', async () => {
    await recordHistory({ kind: 'ad_blocked', domain: 'first.test', storeFullUrls: false });
    await recordHistory({ kind: 'ad_blocked', domain: 'second.test', storeFullUrls: false });
    const history = await getHistory();
    expect(history[0]!.domain).toBe('second.test');
  });

  it('rejects a corrupted history blob', async () => {
    store.set('vbs.history', [{ id: 1, at: 'x', kind: 'evil' }, 'garbage', null]);
    invalidateHistoryCache();
    expect(await getHistory()).toEqual([]);
  });

  it('summarises by kind', async () => {
    await recordHistory({ kind: 'ad_blocked', domain: 'a.test', storeFullUrls: false });
    await recordHistory({ kind: 'ad_blocked', domain: 'b.test', storeFullUrls: false });
    await recordHistory({ kind: 'threat_blocked', domain: 'c.test', storeFullUrls: false });
    const summary = summarize(await getHistory());
    expect(summary.ad_blocked).toBe(2);
    expect(summary.threat_blocked).toBe(1);
  });

  it('clears completely', async () => {
    await recordHistory({ kind: 'ad_blocked', domain: 'a.test', storeFullUrls: false });
    await clearHistory();
    expect(await getHistory()).toEqual([]);
  });
});

describe('settings validation', () => {
  it('returns the documented defaults on a fresh install', async () => {
    const settings = await getSettings();
    expect(settings.protectionEnabled).toBe(true);
    expect(settings.blockAds).toBe(false);
    expect(settings.storeFullUrls).toBe(false);
  });

  it('persists a patch', async () => {
    await updateSettings({ blockAds: true, theme: 'dark' });
    const settings = await getSettings();
    expect(settings.blockAds).toBe(true);
    expect(settings.theme).toBe('dark');
  });

  it('drops unknown keys', async () => {
    await updateSettings({ notARealSetting: true } as never);
    expect(await getSettings() as unknown as Record<string, unknown>).not.toHaveProperty('notARealSetting');
  });

  it('coerces invalid values back to safe defaults', async () => {
    store.set('vbs.settings', { blockAds: 'yes', theme: 'neon', updateIntervalHours: 99999, version: 999 });
    invalidateSettingsCache();
    const settings = await getSettings();
    expect(settings.blockAds).toBe(DEFAULT_SETTINGS.blockAds);
    expect(settings.theme).toBe(DEFAULT_SETTINGS.theme);
    expect(settings.updateIntervalHours).toBeLessThanOrEqual(168);
    expect(settings.version).toBe(DEFAULT_SETTINGS.version);
  });

  it('clamps the update interval into the allowed range', async () => {
    await updateSettings({ updateIntervalHours: 0 });
    expect((await getSettings()).updateIntervalHours).toBeGreaterThanOrEqual(1);
  });

  it('resets', async () => {
    await updateSettings({ blockAds: true });
    await resetSettings();
    expect((await getSettings()).blockAds).toBe(false);
  });
});

describe('allowlist', () => {
  it('normalises a URL to a registrable domain', () => {
    expect(toAllowlistDomain('https://login.example.co.uk/page')).toBe('example.co.uk');
    expect(toAllowlistDomain('example.com')).toBe('example.com');
    expect(toAllowlistDomain('not a domain')).toBeNull();
  });

  it('stores only the domain', async () => {
    await addToAllowlist('https://sub.example.com/deep/path', 'threats');
    const entries = await getAllowlist();
    expect(entries).toHaveLength(1);
    expect(entries[0]!.domain).toBe('example.com');
  });

  it('widens the scope when re-added', async () => {
    await addToAllowlist('example.com', 'privacy');
    await addToAllowlist('example.com', 'all');
    expect((await getAllowlist())[0]!.scope).toBe('all');
  });

  it('toggles and rescopes', async () => {
    await addToAllowlist('example.com', 'privacy');
    expect(await setEntryEnabled('example.com', false)).toBe(true);
    expect((await getAllowlist())[0]!.enabled).toBe(false);
    expect(await setEntryScope('example.com', 'threats')).toBe(true);
    expect((await getAllowlist())[0]!.scope).toBe('threats');
  });

  it('removes', async () => {
    await addToAllowlist('example.com');
    expect(await removeFromAllowlist('example.com')).toBe(true);
    expect(await removeFromAllowlist('example.com')).toBe(false);
    expect(await getAllowlist()).toHaveLength(0);
  });

  it('rejects a corrupt stored list', async () => {
    store.set('vbs.allowlist', [{ domain: 'evil; DROP TABLE', scope: 'all' }, 'garbage', { domain: 'ok.test', scope: 'bogus' }]);
    invalidateAllowlistCache();
    expect(await getAllowlist()).toEqual([]);
  });
});

describe('local data deletion', () => {
  it('reports storage usage', async () => {
    store.set('vbs.settings', { a: 1 });
    const used = await usage();
    expect(used.bytes).toBeGreaterThan(0);
    expect(used.quotaBytes).toBe(10 * 1024 * 1024);
    // Percent is rounded to two decimals, so a tiny value legitimately reads 0.
    expect(used.percent).toBeGreaterThanOrEqual(0);
    expect(used.overSoftLimit).toBe(false);

    store.set('vbs.big', 'x'.repeat(6 * 1024 * 1024));
    const heavy = await usage();
    expect(heavy.overSoftLimit).toBe(true);
  });

  it('deletes only the selected scopes', async () => {
    store.set('vbs.settings', { a: 1 });
    store.set('vbs.stats', { b: 2 });
    store.set('vbs.history', []);
    store.set('vbs.feedDataset', { revision: 1 });

    await clearData({ settings: true, statistics: false, allowlist: true, history: true, threatData: false });

    expect(store.has('vbs.settings')).toBe(false);
    expect(store.has('vbs.stats')).toBe(true);
    expect(store.has('vbs.history')).toBe(false);
    expect(store.has('vbs.feedDataset')).toBe(true);
  });

  it('deletes everything when asked', async () => {
    store.set('vbs.settings', { a: 1 });
    store.set('vbs.threats.phishing-database-domains', 'evil.test');
    store.set('vbs.feedDataset', { revision: 1 });
    await clearData({ settings: true, statistics: true, allowlist: true, history: true, threatData: true });
    expect(store.size).toBe(0);
  });

  it('estimates value size', () => {
    expect(byteSizeOf({ a: 'bcdef' })).toBeGreaterThan(0);
    expect(byteSizeOf(undefined)).toBe(0);
  });
});
