/**
 * declarativeNetRequest rule compilation, quota management and allowlist scoping.
 *
 * These tests enforce the hard limits documented by Chrome and the priority
 * guarantees the specification requires.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import {
  allocateRuleId,
  buildUrlFilter,
  compileAllowRule,
  compileRule,
  planQuota,
  readRuntimeLimits,
  resetRuleIdAllocator,
  RuleCompiler,
} from '../../src/blocking/compiler';
import { buildRules, isCategoryEnabled } from '../../src/blocking/controller';
import { categoryFromRuleId, RULE_CATEGORY_ORDINAL, RULE_CATEGORY_STRIDE, RULE_PRIORITY } from '../../src/core/constants';
import { DEFAULT_SETTINGS, type AllowlistEntry, type Settings } from '../../src/core/types';

// chrome shim: `readRuntimeLimits` probes the real API constants.
(globalThis as Record<string, unknown>).chrome = {
  declarativeNetRequest: {
    MAX_NUMBER_OF_DYNAMIC_RULES: 30_000,
    MAX_NUMBER_OF_UNSAFE_DYNAMIC_RULES: 5_000,
    MAX_NUMBER_OF_SESSION_RULES: 5_000,
  },
};

beforeEach(() => resetRuleIdAllocator(0));

describe('urlFilter construction', () => {
  it('anchors a host with || and ^', () => {
    expect(buildUrlFilter('evil.test')).toBe('||evil.test^');
  });

  it('rejects hosts containing urlFilter metacharacters', () => {
    // `^` and `|` would change the meaning of the filter entirely.
    expect(buildUrlFilter('evil^test')).toBeNull();
    expect(buildUrlFilter('evil|test')).toBeNull();
    expect(buildUrlFilter('evil*test')).toBeNull();
  });

  it('rejects invalid host characters', () => {
    expect(buildUrlFilter('evil_test')).toBeNull();
    expect(buildUrlFilter('')).toBeNull();
    expect(buildUrlFilter('a'.repeat(300))).toBeNull();
  });
});

describe('rule compilation', () => {
  it('blocks main_frame for a threat category', () => {
    resetRuleIdAllocator(0);
    const rule = compileRule({ category: 'phishing', host: 'evil.test' }, allocateRuleId('phishing'));
    expect(rule).not.toBeNull();
    expect(rule!.action.type).toBe('block');
    expect(rule!.priority).toBe(RULE_PRIORITY.BLOCK_PHISHING);
    expect(rule!.condition.urlFilter).toBe('||evil.test^');
    expect(rule!.condition.resourceTypes).toContain('main_frame');
  });

  it('never blocks main_frame for a privacy category', () => {
    resetRuleIdAllocator(0);
    const rule = compileRule({ category: 'tracker', host: 'tracker.test' }, allocateRuleId('tracker'));
    expect(rule!.condition.resourceTypes).not.toContain('main_frame');
  });

  it('applies the third-party restriction only when asked', () => {
    resetRuleIdAllocator(0);
    const third = compileRule({ category: 'ad', host: 'ads.test', thirdParty: true }, allocateRuleId('ad'));
    const first = compileRule({ category: 'ad', host: 'ads.test', thirdParty: false }, allocateRuleId('ad'));
    expect(third!.condition.domainType).toBe('thirdParty');
    expect(first!.condition.domainType).toBeUndefined();
  });

  it('removes excluded resource types', () => {
    resetRuleIdAllocator(0);
    const rule = compileRule(
      { category: 'tracker', host: 't.test', excludedResourceTypes: ['script', 'image'] },
      allocateRuleId('tracker'),
    );
    expect(rule!.condition.resourceTypes).not.toContain('script');
    expect(rule!.condition.resourceTypes).not.toContain('image');
  });

  it('returns null when every resource type is excluded', () => {
    resetRuleIdAllocator(0);
    const rule = compileRule(
      {
        category: 'tracker',
        host: 't.test',
        excludedResourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame', 'media', 'font', 'stylesheet', 'ping', 'websocket', 'other'],
      },
      allocateRuleId('tracker'),
    );
    expect(rule).toBeNull();
  });

  it('produces NO regexFilter anywhere', () => {
    resetRuleIdAllocator(0);
    const rule = compileRule({ category: 'malware', host: 'x.test' }, allocateRuleId('malware'));
    expect(rule!.condition).not.toHaveProperty('regexFilter');
  });
});

describe('rule id encoding', () => {
  it('encodes the category in the high digits', () => {
    resetRuleIdAllocator(0);
    const id = allocateRuleId('phishing');
    expect(Math.floor(id / RULE_CATEGORY_STRIDE)).toBe(RULE_CATEGORY_ORDINAL.phishing);
    expect(categoryFromRuleId(id)).toBe('phishing');
  });

  it('round-trips every category', () => {
    resetRuleIdAllocator(0);
    for (const category of ['malware', 'malware_distribution', 'phishing', 'scam', 'tracker', 'ad'] as const) {
      expect(categoryFromRuleId(allocateRuleId(category))).toBe(category);
    }
  });

  it('never exceeds the Chrome rule id ceiling', () => {
    resetRuleIdAllocator(RULE_CATEGORY_STRIDE - 1);
    for (const category of ['malware', 'malware_distribution', 'phishing', 'scam', 'tracker', 'ad'] as const) {
      expect(allocateRuleId(category)).toBeLessThan(2_147_483_647);
    }
  });

  it('returns null for an unknown bucket', () => {
    expect(categoryFromRuleId(1_000)).toBeNull();
    expect(categoryFromRuleId(999_000_000)).toBeNull();
  });
});

describe('allowlist rule scoping (anti-crosstalk requirement)', () => {
  it('scope=all uses allowAllRequests', () => {
    const rule = compileAllowRule('example.test', 'all', 1_001)!;
    expect(rule.action.type).toBe('allowAllRequests');
    expect(rule.priority).toBe(RULE_PRIORITY.ALLOW_ALL);
  });

  it('scope=threats outranks every threat block band', () => {
    const rule = compileAllowRule('example.test', 'threats', 1_002)!;
    expect(rule.action.type).toBe('allow');
    expect(rule.priority).toBeGreaterThan(RULE_PRIORITY.BLOCK_MALWARE);
    expect(rule.priority).toBeGreaterThan(RULE_PRIORITY.BLOCK_PHISHING);
  });

  it('scope=privacy does NOT outrank malware/phishing blocks', () => {
    // This is the explicit requirement: an ad exception must never disable
    // malware protection.
    const rule = compileAllowRule('example.test', 'privacy', 1_003)!;
    expect(rule.priority).toBeLessThan(RULE_PRIORITY.BLOCK_MALWARE);
    expect(rule.priority).toBeLessThan(RULE_PRIORITY.BLOCK_PHISHING);
    expect(rule.priority).toBeGreaterThan(RULE_PRIORITY.BLOCK_ADS);
  });

  it('threats scope still blocks top-level navigation to the site', () => {
    const rule = compileAllowRule('example.test', 'threats', 1_004)!;
    expect(rule.condition.resourceTypes).not.toContain('main_frame');
  });

  it('rejects an invalid domain', () => {
    expect(compileAllowRule('bad_domain', 'all', 1)).toBeNull();
    expect(compileAllowRule('evil^test', 'all', 1)).toBeNull();
  });
});

describe('quota planning', () => {
  it('reads the real browser limits when available', () => {
    const limits = readRuntimeLimits();
    expect(limits.dynamicSafe).toBe(30_000);
    expect(limits.dynamicUnsafe).toBe(5_000);
    expect(limits.session).toBe(5_000);
  });

  it('applies headroom below the published limit', () => {
    const plan = planQuota({ dynamicSafe: 30_000, dynamicUnsafe: 5_000, session: 5_000 }, 0);
    expect(plan.budget).toBeLessThan(30_000);
    expect(plan.datasetBudget + plan.reservedForAllowlist).toBe(plan.budget);
  });

  it('never returns a negative dataset budget', () => {
    const plan = planQuota({ dynamicSafe: 10, dynamicUnsafe: 5, session: 5 }, 100_000);
    expect(plan.datasetBudget).toBeGreaterThanOrEqual(0);
  });
});

describe('RuleCompiler', () => {
  it('de-duplicates identical inputs', () => {
    const compiler = new RuleCompiler(planQuota({ dynamicSafe: 30_000, dynamicUnsafe: 5_000, session: 5_000 }, 0));
    compiler.add({ category: 'phishing', host: 'a.test' });
    compiler.add({ category: 'phishing', host: 'a.test' });
    expect(compiler.size).toBe(1);
    expect(compiler.report().duplicatesRemoved).toBe(1);
  });

  it('counts invalid hosts instead of silently dropping them', () => {
    const compiler = new RuleCompiler(planQuota({ dynamicSafe: 30_000, dynamicUnsafe: 5_000, session: 5_000 }, 0));
    compiler.add({ category: 'phishing', host: 'bad_host' });
    expect(compiler.report().rejectedInvalidHost).toBe(1);
  });

  it('respects the dataset budget and reports the overflow', () => {
    const compiler = new RuleCompiler({ budget: 5, reservedForAllowlist: 0, datasetBudget: 3 });
    for (let i = 0; i < 10; i += 1) compiler.add({ category: 'phishing', host: `h${i}.test` });
    expect(compiler.size).toBe(3);
    expect(compiler.report().droppedForQuota).toBe(7);
  });
});

describe('buildRules - category gating and priority', () => {
  const datasets = [
    { category: 'malware' as const, hosts: new Set(['m1.test', 'm2.test']), providerId: 'p1', order: 0 },
    { category: 'phishing' as const, hosts: new Set(['p1.test', 'p2.test']), providerId: 'p2', order: 2 },
    { category: 'tracker' as const, hosts: new Set(['t1.test']), providerId: 'p3', order: 4 },
    { category: 'ad' as const, hosts: new Set(['a1.test']), providerId: 'p4', order: 5 },
  ];

  it('skips a disabled category', () => {
    const settings: Settings = { ...DEFAULT_SETTINGS, blockAds: false };
    const result = buildRules({ settings, datasets, allowlist: [] });
    expect(result.installedByCategory.ad ?? 0).toBe(0);
    expect(result.installedByCategory.tracker ?? 0).toBe(1);
  });

  it('produces nothing when protection is off', () => {
    const settings: Settings = { ...DEFAULT_SETTINGS, protectionEnabled: false };
    const result = buildRules({ settings, datasets, allowlist: [] });
    expect(result.rules).toHaveLength(0);
  });

  it('skips allowlisted hosts and their subdomains', () => {
    const allowlist: AllowlistEntry[] = [
      { domain: 'p1.test', scope: 'all', addedAt: 0, enabled: true },
    ];
    const result = buildRules({ settings: DEFAULT_SETTINGS, datasets, allowlist });
    const hosts = result.rules.map((r) => r.condition.urlFilter);
    expect(hosts).not.toContain('||p1.test^');
    expect(hosts).toContain('||p2.test^');
  });

  it('ignores a disabled allowlist entry', () => {
    const allowlist: AllowlistEntry[] = [
      { domain: 'p1.test', scope: 'all', addedAt: 0, enabled: false },
    ];
    const result = buildRules({ settings: DEFAULT_SETTINGS, datasets, allowlist });
    expect(result.rules.map((r) => r.condition.urlFilter)).toContain('||p1.test^');
  });

  it('never exceeds the planned budget even with a huge dataset', () => {
    const huge = [
      { category: 'phishing' as const, hosts: new Set(Array.from({ length: 60_000 }, (_, i) => `h${i}.test`)), providerId: 'p', order: 2 },
    ];
    const result = buildRules({ settings: DEFAULT_SETTINGS, datasets: huge, allowlist: [] });
    expect(result.rules.length).toBeLessThanOrEqual(result.quota.datasetBudget);
    expect(result.truncatedCategories).toContain('phishing');
    expect(result.droppedForQuota).toBeGreaterThan(0);
  });

  it('reports a per-category truncation honestly', () => {
    const many = [
      { category: 'ad' as const, hosts: new Set(Array.from({ length: 5_000 }, (_, i) => `a${i}.test`)), providerId: 'p', order: 5 },
    ];
    const result = buildRules({ settings: { ...DEFAULT_SETTINGS, blockAds: true }, datasets: many, allowlist: [] });
    expect(result.truncatedCategories).toContain('ad');
    expect(result.installedByCategory.ad).toBe(2_500); // documented per-category cap
    expect(result.droppedForQuota).toBe(2_500);
  });

  it('shares one budget across every provider feeding a category', () => {
    // Regression: `ad` and `malware` each come from two providers (EasyList
    // plus StevenBlack). Counting the cap per provider let `ad` install twice
    // its documented budget, quietly consuming quota the threat categories
    // needed.
    //
    // `owner` is how a merged dataset reports per-host provenance; without it
    // the rules carry no attribution.
    const hostOf = (i: number, tag: string) => `host${i.toString().padStart(4, '0')}${tag}.test`;
    const a = new Set(Array.from({ length: 3_000 }, (_, i) => hostOf(i, 'a')));
    const b = new Set(Array.from({ length: 3_000 }, (_, i) => hostOf(i, 'b')));
    const owner = new Map<string, string>();
    for (const h of a) owner.set(h, 'easylist');
    for (const h of b) owner.set(h, 'stevenblack-hosts');

    const result = buildRules({
      settings: { ...DEFAULT_SETTINGS, blockAds: true },
      datasets: [{ category: 'ad', hosts: new Set([...a, ...b]), owner, order: 5 }],
      allowlist: [],
    });

    // The shared cap, not twice it.
    expect(result.installedByCategory.ad).toBe(2_500);
    expect(result.quota.perCategory.ad).toBe(2_500);
    expect(result.rules.length).toBe(2_500);

    // Both providers contributed: the merged set is sampled, not one provider's
    // prefix.
    expect(new Set(result.rules.map((r) => r.providerId))).toEqual(new Set(['easylist', 'stevenblack-hosts']));
  });

  it('attributes each rule to the provider that actually listed the host', () => {
    const owner = new Map([
      ['from-easylist.test', 'easylist'],
      ['from-stevenblack.test', 'stevenblack-hosts'],
    ]);
    const result = buildRules({
      settings: { ...DEFAULT_SETTINGS, blockAds: true },
      datasets: [{ category: 'ad', hosts: new Set(owner.keys()), owner, order: 5 }],
      allowlist: [],
    });
    const attribution = new Map(result.rules.map((r) => [r.condition.urlFilter, r.providerId]));

    expect(attribution.get('||from-easylist.test^')).toBe('easylist');
    expect(attribution.get('||from-stevenblack.test^')).toBe('stevenblack-hosts');
  });

  it('retains hosts from the whole alphabet, not just an early prefix', () => {
    /*
     * Regression. Two selection steps - an even stride in the assembler followed
     * by a prefix slice in the compiler - cancelled each other out and collapsed
     * the installed rules back onto the first few letters. Real ad networks
     * listed in EasyList (`static.doubleclick.net`, `pagead2.googlesyndication.com`)
     * sort far past that prefix and were silently never installed.
     */
    const hosts = new Set<string>();
    // A wide alphabet: two letters per "region", 400 hosts each = 20,800 total.
    for (let region = 0; region < 26; region += 1) {
      const prefix = String.fromCharCode(97 + (region % 26));
      const second = String.fromCharCode(97 + Math.floor(region / 26));
      for (let i = 0; i < 400; i += 1) hosts.add(`${prefix}${second}${i.toString().padStart(4, '0')}.test`);
    }

    const result = buildRules({
      settings: { ...DEFAULT_SETTINGS, blockAds: true },
      datasets: [{ category: 'ad', hosts, order: 5 }],
      allowlist: [],
    });

    const installed = result.rules.map((r) => (r.condition.urlFilter ?? '').replace(/^\|\|/, ''));
    const firstLetters = new Set(installed.map((h) => h[0]));
    expect(firstLetters.size, 'the sample collapsed onto too few starting letters').toBeGreaterThanOrEqual(20);

    /*
     * Coverage must reach the END of the alphabet too. An even stride does not
     * guarantee the literal last element (the step lands between indices), so the
     * assertion is on the final REGION, which is what "not an early prefix"
     * actually means.
     */
    const finalRegion = installed.filter((h) => h.startsWith('za')).length;
    expect(finalRegion, 'nothing from the end of the alphabet was retained').toBeGreaterThan(0);
    expect(finalRegion, 'the sample is heavily skewed toward the start').toBeGreaterThan(10);
  });

  it('does not let one over-supplied category starve the threat categories', () => {
    // A flood of ad and tracker hosts must not consume the quota phishing needs.
    const flood = [
      { category: 'ad' as const, hosts: new Set(Array.from({ length: 50_000 }, (_, i) => `ad${i}.test`)), providerId: 'p1', order: 5 },
      { category: 'tracker' as const, hosts: new Set(Array.from({ length: 50_000 }, (_, i) => `tr${i}.test`)), providerId: 'p2', order: 4 },
      { category: 'phishing' as const, hosts: new Set(Array.from({ length: 20_000 }, (_, i) => `ph${i}.test`)), providerId: 'p3', order: 2 },
    ];
    const result = buildRules({
      settings: { ...DEFAULT_SETTINGS, blockAds: true, blockTrackers: true, blockPhishing: true },
      datasets: flood,
      allowlist: [],
    });

    expect(result.installedByCategory.phishing).toBe(13_000);
    expect(result.rules.length).toBeLessThanOrEqual(result.quota.datasetBudget);
  });
});

describe('isCategoryEnabled', () => {
  it('maps each category to its own setting', () => {
    const settings: Settings = { ...DEFAULT_SETTINGS, blockTrackers: false };
    expect(isCategoryEnabled(settings, 'tracker')).toBe(false);
    expect(isCategoryEnabled(settings, 'phishing')).toBe(true);
  });
});
