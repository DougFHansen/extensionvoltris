/**
 * Multi-layer risk engine: verdicts, scoring and FALSE-POSITIVE policy.
 *
 * The engine depends on `chrome.storage`, so this file installs a minimal,
 * in-memory implementation of the extension APIs the engine touches. No browser
 * and no network are involved.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

// ---------------------------------------------------------------- chrome shim

const store = new Map<string, unknown>();

function installChromeShim(): void {
  const localArea = {
    get: async (keys: string | string[] | null) => {
      if (keys === null || keys === undefined) return Object.fromEntries(store);
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const key of list) if (store.has(key)) out[key] = store.get(key);
      return out;
    },
    set: async (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
    },
    remove: async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) store.delete(key);
    },
    clear: async () => store.clear(),
  };

  (globalThis as Record<string, unknown>).chrome = {
    storage: { local: localArea, session: localArea, onChanged: { addListener: () => undefined, removeListener: () => undefined } },
    runtime: { getURL: (p: string) => `chrome-extension://test/${p}`, getManifest: () => ({ permissions: [] }) },
  };
}

installChromeShim();

// ------------------------------------------------------------------- imports

const { analyzeUrl } = await import('../../src/security/risk');
const { setPslRootForTests, resetPslForTests } = await import('../../src/security/psl');
const { invalidateReputationCache, decodeDomains } = await import('../../src/security/reputation');
const { categoryForProvider } = await import('../../src/security/reputation');

const PSL = JSON.parse(readFileSync('src/generated/psl.json', 'utf8')) as { root: unknown };
setPslRootForTests(PSL.root as never, {
  source: 'test',
  license: 'MPL-2.0',
  sha256: 'b'.repeat(64),
  generatedAt: '2026-01-01',
  ruleCount: 10336,
});

const { DEFAULT_SETTINGS } = await import('../../src/core/types');

const OPTS = {
  settings: DEFAULT_SETTINGS,
  allowlisted: new Set<string>(),
};

beforeEach(() => {
  store.clear();
  invalidateReputationCache();
});

/** Seeds a verified feed with fictional domains. */
async function seedThreats(providerId: string, domains: string[]): Promise<void> {
  const state = {
    id: providerId,
    status: 'active',
    lastSuccessAt: Date.now(),
    lastAttemptAt: Date.now(),
    lastError: null,
    entryCount: domains.length,
    ruleCount: 0,
    contentHash: 'c'.repeat(64),
    feedVersion: '20260101',
    skipped: 0,
    skippedByReason: {},
  };
  await chrome.storage.local.set({
    'vbs.threats.__meta': [state],
    [`vbs.threats.${providerId}`]: [...domains].sort().join('\n'),
  });
  invalidateReputationCache();
}

// ------------------------------------------------------------------ verdicts

describe('classification - known malicious', () => {
  it('reports a feed-listed phishing domain as known malicious', async () => {
    await seedThreats('phishing-database-domains', ['evil-login.test']);
    const result = await analyzeUrl('https://evil-login.test/verify', OPTS);
    expect(result.verdict).toBe('known-malicious');
    expect(result.categories).toContain('phishing');
    expect(result.sources.length).toBe(1);
    expect(result.sources[0]!.providerId).toBe('phishing-database-domains');
    expect(result.confidence).toBe('high');
  });

  it('matches a parent domain present in the feed', async () => {
    await seedThreats('phishing-database-domains', ['badbank.test']);
    const result = await analyzeUrl('https://login.badbank.test/a', OPTS);
    expect(result.verdict).toBe('known-malicious');
  });

  it('refuses to call a stale feed a live detection', async () => {
    await chrome.storage.local.set({
      'vbs.threats.__meta': [
        {
          id: 'phishing-database-domains',
          status: 'error',
          lastSuccessAt: null,
          lastAttemptAt: Date.now(),
          lastError: 'http: 503',
          entryCount: 0,
          ruleCount: 0,
          contentHash: null,
          feedVersion: null,
          skipped: 0,
          skippedByReason: {},
        },
      ],
      'vbs.threats.phishing-database-domains': 'broken.test',
    });
    invalidateReputationCache();
    const result = await analyzeUrl('https://broken.test/', OPTS);
    expect(result.verdict).not.toBe('known-malicious');
  });

  it('never calls a host malicious merely because the engine is disabled', async () => {
    await seedThreats('phishing-database-domains', ['evil.test']);
    const result = await analyzeUrl('https://evil.test/', { ...OPTS, settings: { ...DEFAULT_SETTINGS, phishingEngineEnabled: false } });
    expect(result.verdict).toBe('not-analyzed');
  });

  it('reports protection-disabled state as not analysed', async () => {
    const result = await analyzeUrl('https://example.test/', { ...OPTS, settings: { ...DEFAULT_SETTINGS, protectionEnabled: false } });
    expect(result.verdict).toBe('not-analyzed');
    expect(result.reasons[0]!.code).toBe('coverage.disabled_module');
  });
});

describe('classification - heuristics never assert malice', () => {
  it('classifies a heavy impersonation as suspicious, not malicious', async () => {
    const result = await analyzeUrl('https://paypal.com.secure-login.test/', OPTS);
    expect(result.verdict).toBe('suspicious');
    expect(result.categories).toHaveLength(0); // no feed-backed category
    expect(result.sources).toHaveLength(0);
    expect(result.reasons.some((r) => r.code === 'brand_impersonation_subdomain')).toBe(true);
  });

  it('classifies a fullwidth homograph as suspicious', async () => {
    // Fullwidth Latin parses through IDNA into a punycode label whose skeleton
    // is an ordinary Latin word - the classic fullwidth homograph.
    const result = await analyzeUrl('https://\uff50aypal.test/', OPTS);
    expect(result.verdict).toBe('suspicious');
    expect(result.categories).toHaveLength(0);
  });

  it('refuses a host containing a bidi override as not analysed', async () => {
    // The URL parser rejects these hosts, exactly as the browser does. The
    // engine reports `not-analyzed` instead of guessing.
    const result = await analyzeUrl('https://paypal\u202etest/', OPTS);
    expect(result.verdict).toBe('not-analyzed');
    expect(result.reasons.some((r) => r.code === 'coverage.no_reputation_data')).toBe(true);
  });

  it('never escalates a heuristic to known-malicious regardless of score', async () => {
    const hostile = 'https://secure.paypal.com.br.login-verificacao.mixed-script.test/';
    const result = await analyzeUrl(hostile, OPTS);
    expect(result.verdict).not.toBe('known-malicious');
    expect(result.categories).toHaveLength(0);
  });
});

describe('FALSE POSITIVE policy (explicit specification requirement)', () => {
  it('does not treat a missing HTTPS as a threat', async () => {
    const result = await analyzeUrl('http://example.test/page', OPTS);
    expect(result.verdict).toBe('no-threat-found');
    expect(result.reasons.filter((r) => r.code === 'suspicious_url_shape')).toHaveLength(0);
  });

  it('does not treat many subdomains as a threat', async () => {
    const result = await analyzeUrl('https://a.b.c.d.e.f.example.test/', OPTS);
    expect(result.verdict).toBe('no-threat-found');
  });

  it('does not treat the word "login" as a threat', async () => {
    for (const url of ['https://login.example.test/', 'https://example.test/login', 'https://signin.example.test/']) {
      const result = await analyzeUrl(url, OPTS);
      expect(result.verdict, url).toBe('no-threat-found');
    }
  });

  it('does not flag a legitimate punycode-only IDN domain', async () => {
    const result = await analyzeUrl('https://xn--e1afmkfd.xn--p1ai/', OPTS);
    expect(result.verdict).toBe('no-threat-found');
  });

  it('does not flag punycode as malicious on its own', async () => {
    const result = await analyzeUrl('https://xn--80ak6aa92e.test/', OPTS);
    expect(result.verdict).not.toBe('known-malicious');
  });

  it('does not flag Google ad infrastructure as brand impersonation', async () => {
    for (const url of ['https://googleadservices.com/pagead/js', 'https://www.googletagmanager.com/gtm.js']) {
      const result = await analyzeUrl(url, OPTS);
      expect(result.verdict, url).toBe('no-threat-found');
    }
  });

  it('does not flag the brand\'s own domain', async () => {
    for (const url of ['https://www.paypal.com/', 'https://checkout.paypal.com.br/']) {
      const result = await analyzeUrl(url, OPTS);
      expect(result.verdict, url).toBe('no-threat-found');
    }
  });

  it('treats an IP literal as low-confidence, not as malicious', async () => {
    const result = await analyzeUrl('http://203.0.113.10/', OPTS);
    expect(result.verdict).not.toBe('known-malicious');
    expect(result.reasons.find((r) => r.code === 'ip_literal_host')?.confidence).toBe('medium');
  });
});

describe('coverage honesty', () => {
  it('returns not-analyzed for an unparsable input', async () => {
    const result = await analyzeUrl('not a url at all', OPTS);
    expect(result.verdict).toBe('not-analyzed');
  });

  it('returns not-analyzed for an IP literal (no reputation coverage)', async () => {
    const result = await analyzeUrl('http://203.0.113.10/', OPTS);
    expect(result.verdict).toBe('not-analyzed');
  });

  it('returns not-analyzed for a single-label host', async () => {
    const result = await analyzeUrl('http://intranet/', OPTS);
    expect(result.verdict).toBe('not-analyzed');
  });

  it('never claims a clean verdict when the input cannot be parsed', async () => {
    for (const input of ['', '   ', 'javascript:alert(1)', 'data:text/html,x', 'chrome://settings', null, undefined, 123]) {
      const result = await analyzeUrl(input, OPTS);
      expect(result.verdict).not.toBe('no-threat-found');
    }
  });
});

describe('allowlist interaction', () => {
  it('keeps the verdict factual while flagging the user exception', async () => {
    // Allowlisting changes what we BLOCK, never what we KNOW. The verdict stays
    // `known-malicious` and `allowlisted` is surfaced so the UI can explain it.
    await seedThreats('phishing-database-domains', ['shop.test']);
    const result = await analyzeUrl('https://shop.test/', { ...OPTS, allowlisted: new Set(['shop.test']) });
    expect(result.verdict).toBe('known-malicious');
    expect(result.allowlisted).toBe(true);
    expect(result.reasons.some((r) => r.code === 'coverage.allowlisted')).toBe(true);
  });

  it('does not let an allowlist entry cover a different registrable domain', async () => {
    await seedThreats('phishing-database-domains', ['shop.test']);
    // `shop.test.evil.test` has registrable domain `evil.test`; being listed as
    // `shop.test` says nothing about it.
    const unrelated = await analyzeUrl('https://shop.test.evil.test/', { ...OPTS, allowlisted: new Set(['shop.test']) });
    expect(unrelated.verdict).not.toBe('known-malicious');

    // Allowlisting an unrelated domain must not protect the listed one.
    const other = await analyzeUrl('https://shop.test/', { ...OPTS, allowlisted: new Set(['other.test']) });
    expect(other.verdict).toBe('known-malicious');
  });

  it('matches a parent domain present in the feed', async () => {
    await seedThreats('phishing-database-domains', ['badbank.test']);
    const result = await analyzeUrl('https://login.badbank.test/a', OPTS);
    expect(result.verdict).toBe('known-malicious');
    expect(result.reasons.some((r) => (r.data?.matched as string | undefined) === 'badbank.test')).toBe(true);
  });
});

describe('explanation quality', () => {
  it('every reason carries a code, weight, confidence and severity', async () => {
    await seedThreats('phishing-database-domains', ['evil.test']);
    const result = await analyzeUrl('https://evil.test/', OPTS);
    for (const reason of result.reasons) {
      expect(reason.code).toBeTruthy();
      expect(Number.isFinite(reason.weight)).toBe(true);
      expect(['high', 'medium', 'low']).toContain(reason.confidence);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(reason.severity);
    }
  });

  it('records the active modules', async () => {
    const result = await analyzeUrl('https://example.test/', OPTS);
    expect(result.modulesActive).toContain('reputation');
    expect(result.modulesActive).toContain('unicode');
    expect(result.modulesActive).toContain('impersonation');
  });
});

describe('provider category mapping', () => {
  it('maps safety providers to safety categories and never to ads', () => {
    expect(categoryForProvider('phishing-database-domains')).toBe('phishing');
    expect(categoryForProvider('stevenblack-hosts')).toBe('malware');
    expect(categoryForProvider('unknown-provider')).toBe('malware');
  });
});
