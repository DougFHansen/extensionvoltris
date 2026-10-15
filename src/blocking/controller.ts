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
  readonly hosts: ReadonlySet<string>;
  readonly providerId: string;
  /** Lower runs first and therefore wins when the quota is tight. */
  readonly order: number;
}

/**
 * Per-category share of the rule budget.
 * Threat categories get an absolute guarantee; the remainder is split between
 * trackers and ads. The numbers are deliberately conservative so the extension
 * co-exists with other blockers.
 */
const CATEGORY_BUDGET: Record<ThreatCategory, number> = {
  malware: 4_000,
  phishing: 14_000,
  malware_distribution: 2_000,
  scam: 2_000,
  tracker: 4_000,
  ad: 2_000,
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

  for (const dataset of enabled) {
    const cap = CATEGORY_BUDGET[dataset.category];
    perCategoryCap[dataset.category] = cap;
    let added = 0;
    let skipped = 0;

    // Deterministic iteration order: the datasets are Sets built from sorted
    // feed data, so the same truncation happens on every run.
    for (const rawHost of dataset.hosts) {
      if (added >= cap || compiler.size >= quota.datasetBudget) {
        skipped += 1;
        continue;
      }
      const host = normalizeHostname(rawHost);
      if (host === null) continue;
      if (isAllowlistedHost(host, allowlisted)) continue;

      const ok = compiler.add({
        category: dataset.category,
        host,
        providerId: dataset.providerId,
        ...(dataset.category === 'tracker' || dataset.category === 'ad' ? { thirdParty: input.settings.blockThirdPartyOnly } : {}),
      });
      if (ok) added += 1;
    }

    if (skipped > 0) {
      truncated.push(dataset.category);
      droppedForCategoryCap += skipped;
    }
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
