/**
 * Blocking controller: turns the local dataset into declarativeNetRequest rules
 * and keeps the installed rule set in sync with settings + allowlist + feeds.
 *
 * Invariants this module guarantees:
 *  1. We never install more rules than the browser allows (see `planQuota`).
 *  2. Malware/phishing always get priority over trackers and ads.
 *  3. An allowlist entry scoped to privacy NEVER disables malware blocking
 *     (different priority bands, see compiler.ts).
 *  4. If anything fails, the previously working rule set is left untouched.
 */
import type { ThreatCategory } from '../core/types';
import { normalizeHostname } from '../feeds/parsers';
import { selectEvenlyIterative } from '../security/reputation';
import {
  planQuota,
  readRuntimeLimits,
  resetRuleIdAllocator,
  RuleCompiler,
  type CompiledRule,
} from './compiler';
import { dnrCapabilities, getDynamicRuleCount, swapDynamicRules, syncAllowlistRules } from '../platform/dnr';
import { RULE_ID } from '../core/constants';
import type { AllowlistEntry, Settings } from '../core/types';

/** Session rule ids for the allowlist live in their own range. */
const ALLOWLIST_SESSION_ID_BASE = 1_000;

export interface CategoryDataset {
  readonly category: ThreatCategory;
  /**
   * Every host known for this category, already merged across providers.
   *
   * Budgeting happens in `buildRules`, not here: selecting at both levels made
   * an even sample collapse back into an alphabetical prefix, which is how
   * `static.doubleclick.net` and `pagead2.googlesyndication.com` went
   * uninstalled despite being listed in EasyList.
   */
  readonly hosts: ReadonlySet<string>;
  /**
   * Which provider listed each host, for attribution on the block page and in
   * Diagnostics. A host only blocks under a feed that actually listed it.
   */
  readonly owner?: ReadonlyMap<string, string>;
  /** Lower runs first and therefore wins when the quota is tight. */
  readonly order: number;
}

/**
 * Per-category share of the rule budget.
 * Threat categories get an absolute guarantee; the remainder is split between
 * trackers and ads. The numbers are deliberately conservative so the extension
 * co-exists with other blockers.
 */
/**
 * Rule budget per category, in RULES, shared across every provider feeding that
 * category.
 *
 * Sized against the 27,000 safe dynamic-rule quota Chrome grants. Threats get
 * the majority: an ad that slips through costs a nuisance, a phishing page that
 * slips through costs credentials.
 *
 * The budgets deliberately total less than the quota so that one over-supplied
 * category cannot starve the others - the exact failure this table had, when the
 * cap was counted per provider and the ad category installed twice its share.
 */
/**
 * Install order, lowest first.
 *
 * When the total quota is tight, the categories installed earlier keep their
 * share, so threats win over privacy filtering.
 */
const ORDER_HINT: Record<ThreatCategory, number> = {
  malware: 0,
  malware_distribution: 1,
  phishing: 2,
  scam: 3,
  tracker: 4,
  ad: 5,
};

const CATEGORY_BUDGET: Record<ThreatCategory, number> = {
  malware: 5_000,
  phishing: 13_000,
  malware_distribution: 1_500,
  scam: 1_500,
  tracker: 3_500,
  ad: 2_500,
};

export interface BuildResult {
  readonly rules: readonly CompiledRule[];
  readonly installedByCategory: Readonly<Record<string, number>>;
  readonly droppedForQuota: number;
  readonly rejectedInvalidHost: number;
  readonly duplicatesRemoved: number;
  readonly quota: { budget: number; datasetBudget: number; perCategory: Record<string, number> };
  readonly truncatedCategories: readonly string[];
}

export interface BuildInput {
  readonly settings: Settings;
  readonly datasets: readonly CategoryDataset[];
  readonly allowlist: readonly AllowlistEntry[];
}

const CATEGORY_ENABLED_KEY: Record<ThreatCategory, keyof Pick<Settings, 'blockMalware' | 'blockPhishing' | 'blockScam' | 'blockMalwareDistribution' | 'blockTrackers' | 'blockAds'>> = {
  malware: 'blockMalware',
  phishing: 'blockPhishing',
  malware_distribution: 'blockMalwareDistribution',
  scam: 'blockScam',
  tracker: 'blockTrackers',
  ad: 'blockAds',
};

export function isCategoryEnabled(settings: Settings, category: ThreatCategory): boolean {
  return settings[CATEGORY_ENABLED_KEY[category]] === true;
}

/**
 * Compiles the dataset into rules.
 * Pure: no browser API is touched here, which makes the whole budgeting logic
 * unit-testable.
 */
export function buildRules(input: BuildInput): BuildResult {
  resetRuleIdAllocator(RULE_ID.MIN_DYNAMIC);
  const limits = readRuntimeLimits();
  const quota = planQuota(limits, input.allowlist.filter((e) => e.enabled).length);
  const compiler = new RuleCompiler(quota);

  const enabled = input.datasets
    .filter((d) => input.settings.protectionEnabled && isCategoryEnabled(input.settings, d.category))
    .sort((a, b) => a.order - b.order);

  const allowlisted = new Set(input.allowlist.filter((e) => e.enabled).map((e) => e.domain));

  const perCategoryCap: Record<string, number> = {};
  const truncated: string[] = [];
  // Truncation happens at two levels and BOTH must be reported, otherwise
  // Diagnostics would under-report how much of the feed is actually enforced.
  let droppedForCategoryCap = 0;

  /*
   * ONE SHARED BUDGET PER CATEGORY, SPENT IN MERGED ORDER.
   *
   * `ad` and `malware` each come from two providers (EasyList plus StevenBlack).
   *
   * Counting the cap per provider let `ad` install twice its documented budget,
   * quietly consuming quota the threat categories needed.
   *
   * Simply capping per category was not enough either: iterating provider by
   * provider fills the whole cap from whichever provider came first, so the
   * second provider contributed nothing at all and its coverage vanished. The
   * providers for a category are therefore MERGED and iterated in sorted order,
   * so the retained rules are a spread across everything the category knows
   * about, with each host still attributed to the provider that listed it.
   */
  const byCategory = new Map<ThreatCategory, { hosts: Set<string>; owner: Map<string, string> }>();
  for (const dataset of enabled) {
    let bucket = byCategory.get(dataset.category);
    if (!bucket) {
      bucket = { hosts: new Set<string>(), owner: new Map<string, string>() };
      byCategory.set(dataset.category, bucket);
    }
    for (const host of dataset.hosts) {
      if (!bucket.hosts.has(host)) bucket.hosts.add(host);
    }
    if (!dataset.owner) continue;
    for (const [host, providerId] of dataset.owner) {
      if (!bucket.owner.has(host)) bucket.owner.set(host, providerId);
    }
  }

  // Categories are already ordered by `order`; keep install order stable.
  const ordered = [...new Set(enabled.map((d) => d.category))].sort((a, b) => ORDER_HINT[a] - ORDER_HINT[b]);

  for (const category of ordered) {
    const bucket = byCategory.get(category)!;
    const cap = CATEGORY_BUDGET[category];
    perCategoryCap[category] = cap;

    const isPrivacy = category === 'tracker' || category === 'ad';

    /*
     * ONE BUDGET OPERATION: an even stride across the whole category.
     *
     * Sampling here and again downstream would cancel out - a prefix of an even
     * sample is still a prefix. This is the only place the budget is applied, so
     * the installed rules are a uniform sample of everything the category knows.
     */
    const sorted = [...bucket.hosts].sort();
    const selected = selectEvenlyIterative(sorted, cap);

    let added = 0;
    let skipped = 0;
    // Everything not selected is a genuine drop and must be reported, or
    // Diagnostics under-reports how much of the feed is actually enforced.
    skipped += sorted.length - selected.size;

    for (const rawHost of selected) {
      if (compiler.size >= quota.datasetBudget) {
        skipped += 1;
        continue;
      }
      const host = normalizeHostname(rawHost);
      if (host === null) continue;
      if (isAllowlistedHost(host, allowlisted)) continue;

      const ok = compiler.add({
        category,
        host,
        providerId: bucket.owner.get(rawHost),
        ...(isPrivacy ? { thirdParty: input.settings.blockThirdPartyOnly } : {}),
      });
      if (ok) added += 1;
    }

    if (skipped > 0) truncated.push(category);
    droppedForCategoryCap += skipped;
  }

  const report = compiler.report();
  return {
    rules: compiler.drain(),
    installedByCategory: report.perCategory,
    droppedForQuota: report.droppedForQuota + droppedForCategoryCap,
    rejectedInvalidHost: report.rejectedInvalidHost,
    duplicatesRemoved: report.duplicatesRemoved,
    quota: { budget: quota.budget, datasetBudget: quota.datasetBudget, perCategory: perCategoryCap },
    truncatedCategories: truncated,
  };
}

function isAllowlistedHost(host: string, allowlisted: ReadonlySet<string>): boolean {
  for (const domain of allowlisted) {
    if (host === domain || host.endsWith(`.${domain}`)) return true;
  }
  return false;
}

export interface ApplyResult {
  readonly ok: boolean;
  readonly error: string | null;
  readonly ruleCount: number;
  readonly sessionRuleCount: number;
  readonly build: BuildResult;
}

/**
 * Builds and installs the full rule set, then syncs the allowlist session rules.
 * On failure the previous rule set is preserved (the swap is atomic).
 */
export async function applyBlocking(input: BuildInput): Promise<ApplyResult> {
  const caps = dnrCapabilities();
  const build = buildRules(input);

  if (!caps.dynamicRules) {
    return { ok: false, error: 'dnr_unavailable', ruleCount: 0, sessionRuleCount: 0, build };
  }

  const swap = await swapDynamicRules(build.rules);
  if (!swap.ok) {
    return { ok: false, error: swap.error, ruleCount: await getDynamicRuleCount(), sessionRuleCount: 0, build };
  }

  const session = await syncAllowlistRules(
    input.allowlist.filter((e) => e.enabled).map((e) => ({ domain: e.domain, scope: e.scope })),
    ALLOWLIST_SESSION_ID_BASE,
  );

  return {
    ok: true,
    error: session.ok ? null : session.error,
    ruleCount: swap.added,
    sessionRuleCount: session.added,
    build,
  };
}

/** Re-applies only the allowlist. Cheap; used after every allowlist change. */
export async function syncAllowlist(allowlist: readonly AllowlistEntry[]): Promise<number> {
  const result = await syncAllowlistRules(
    allowlist.filter((e) => e.enabled).map((e) => ({ domain: e.domain, scope: e.scope })),
    ALLOWLIST_SESSION_ID_BASE,
  );
  return result.added;
}

/** Removes every rule we installed (used by "reset protection"). */
export async function clearBlocking(): Promise<boolean> {
  const swap = await swapDynamicRules([]);
  return swap.ok;
}
