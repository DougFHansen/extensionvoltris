/**
 * Dataset assembly: turns the packed feed data plus the registry into the
 * category datasets consumed by the blocking controller, and feeds the local
 * reputation index.
 *
 * This module is the bridge between `feeds/` and `blocking/`. Keeping it separate
 * means the compiler stays a pure function that can be exhaustively unit-tested.
 */
import type { ProviderState, ThreatCategory } from '../core/types';
import { PROVIDER_INDEX } from '../feeds/registry';
import { decodeDomains } from '../security/reputation';
import { applyBlocking, type CategoryDataset } from '../blocking/controller';
import { replaceReputation } from '../security/reputation';
import type { Dataset } from '../feeds/updater';
import type { AllowlistEntry, Settings } from '../core/types';
import type { BuildResult } from '../blocking/controller';

/**
 * Install order. Lower runs first, so when the rule quota is tight the highest
 * value categories survive the truncation.
 */
const ORDER_BY_CATEGORY: Record<ThreatCategory, number> = {
  malware: 0,
  malware_distribution: 1,
  phishing: 2,
  scam: 3,
  tracker: 4,
  ad: 5,
};

/** Providers that contribute reputation data (not just network blocking). */
const REPUTATION_PROVIDERS = new Set(['phishing-database-domains', 'phishing-database-links', 'stevenblack-hosts']);

function isUsableState(state: ProviderState): boolean {
  return state.status === 'active' || state.status === 'stale' || state.status === 'bundled_snapshot';
}

/** Decodes a provider's packed host list into a Set, honouring the quota. */
function hostSetFor(dataset: Dataset, providerId: string): Set<string> {
  const packed = dataset.domainsByProvider.get(providerId);
  return packed ? decodeDomains(packed) : new Set<string>();
}

export interface AssembleResult {
  readonly datasets: readonly CategoryDataset[];
  readonly reputationByProvider: ReadonlyMap<string, string>;
  readonly usableProviders: readonly string[];
  readonly skippedProviders: readonly string[];
}

export function assembleDatasets(dataset: Dataset): AssembleResult {
  const byCategory = new Map<ThreatCategory, Map<string, Set<string>>>();
  const reputationByProvider = new Map<string, string>();
  const usable: string[] = [];
  const skipped: string[] = [];

  for (const state of dataset.states) {
    const descriptor = PROVIDER_INDEX.get(state.id);
    if (!descriptor) continue;
    if (!isUsableState(state)) {
      skipped.push(state.id);
      continue;
    }

    const hosts = hostSetFor(dataset, state.id);
    if (hosts.size === 0) {
      skipped.push(state.id);
      continue;
    }

    usable.push(state.id);

    for (const category of descriptor.categories) {
      let bucket = byCategory.get(category);
      if (!bucket) {
        bucket = new Map();
        byCategory.set(category, bucket);
      }
      const existing = bucket.get(state.id);
      if (existing) {
        for (const host of hosts) existing.add(host);
      } else {
        bucket.set(state.id, new Set(hosts));
      }
    }

    if (REPUTATION_PROVIDERS.has(state.id)) {
      reputationByProvider.set(state.id, dataset.domainsByProvider.get(state.id) ?? '');
    }
  }

  const datasets: CategoryDataset[] = [];
  for (const [category, bucket] of byCategory) {
    for (const [providerId, hosts] of bucket) {
      datasets.push({ category, hosts, providerId, order: ORDER_BY_CATEGORY[category] });
    }
  }

  return { datasets, reputationByProvider, usableProviders: usable, skippedProviders: skipped };
}

/**
 * Full refresh: persists the reputation index, rebuilds and installs the rule
 * set and returns the resulting build report.
 */
export async function refreshProtection(
  dataset: Dataset,
  settings: Settings,
  allowlist: readonly AllowlistEntry[],
): Promise<{ ok: boolean; error: string | null; build: BuildResult; ruleCount: number; sessionRuleCount: number }> {
  const assembled = assembleDatasets(dataset);

  if (assembled.reputationByProvider.size > 0) {
    await replaceReputation(dataset.states, assembled.reputationByProvider);
  }

  const result = await applyBlocking({ settings, datasets: assembled.datasets, allowlist });
  return {
    ok: result.ok,
    error: result.error,
    build: result.build,
    ruleCount: result.ruleCount,
    sessionRuleCount: result.sessionRuleCount,
  };
}
