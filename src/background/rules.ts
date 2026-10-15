/**
 * Rule lifecycle management for the service worker.
 *
 * Responsibilities:
 *  - Ensure the installed rule set matches the current (dataset, settings,
 *    allowlist) triple after a browser restart, an extension update or a
 *    suspension.
 *  - Single-flight: concurrent triggers share one in-flight promise.
 *  - Throttled: repeated triggers inside `MIN_REBUILD_INTERVAL_MS` are ignored.
 */
import type { ProviderState, Settings } from '../core/types';
import { loadDataset, updateFeeds } from '../feeds/updater';
import { refreshProtection, assembleDatasets } from '../blocking/dataset';
import { buildRules } from '../blocking/controller';
import { getSettings } from '../data/settings';
import { getAllowlist } from '../data/allowlist';
import { dnrCapabilities, getDynamicRuleCount, getSessionRuleCount } from '../platform/dnr';
import { pslStatus } from '../security/psl';
import { get, set, K } from '../platform/storage';
import { set as setSession, K as SESSION_KEYS } from '../platform/storage';

const MIN_REBUILD_INTERVAL_MS = 5_000;

let inFlight: Promise<void> | null = null;
let lastRebuildAt = 0;

export interface RulesMeta {
  readonly revision: number;
  readonly installedAt: number;
  readonly ruleCount: number;
  readonly sessionRuleCount: number;
  readonly installedByCategory: Readonly<Record<string, number>>;
  readonly droppedForQuota: number;
  readonly truncatedCategories: readonly string[];
}

export async function ensureRules(force = false): Promise<void> {
  if (!dnrCapabilities().dynamicRules) return;
  const now = Date.now();
  if (!force && now - lastRebuildAt < MIN_REBUILD_INTERVAL_MS) return;
  if (inFlight) return inFlight;

  inFlight = (async () => {
    try {
      const settings = await getSettings();
      const allowlist = await getAllowlist();
      const dataset = await loadDataset();

      const installed = await refreshProtection(dataset, settings, allowlist);
      lastRebuildAt = Date.now();

      const meta: RulesMeta = {
        revision: dataset.revision,
        installedAt: Date.now(),
        ruleCount: installed.ruleCount,
        sessionRuleCount: installed.sessionRuleCount,
        installedByCategory: installed.build.installedByCategory,
        droppedForQuota: installed.build.droppedForQuota,
        truncatedCategories: installed.build.truncatedCategories,
      };
      await set(K.rulesMeta, meta);
      if (!installed.ok && installed.error) {
        await setSession(`${SESSION_KEYS.blockEvents}.lastError`, installed.error, 'session');
      }
    } finally {
      inFlight = null;
    }
  })();

  return inFlight;
}

export async function getRulesMeta(): Promise<RulesMeta | null> {
  return get<RulesMeta>(K.rulesMeta);
}

export interface ProtectionState {
  readonly protectionEnabled: boolean;
  readonly capabilities: ReturnType<typeof dnrCapabilities>;
  readonly dynamicRuleCount: number;
  readonly sessionRuleCount: number;
  readonly rulesMeta: RulesMeta | null;
  readonly datasetRevision: number;
  readonly datasetUpdatedAt: number;
  readonly psl: ReturnType<typeof pslStatus>;
}

export async function getProtectionState(): Promise<ProtectionState> {
  const settings = await getSettings();
  const [dynamicRuleCount, sessionRuleCount, rulesMeta, dataset] = await Promise.all([
    getDynamicRuleCount(),
    getSessionRuleCount(),
    getRulesMeta(),
    loadDataset(),
  ]);
  return {
    protectionEnabled: settings.protectionEnabled,
    capabilities: dnrCapabilities(),
    dynamicRuleCount,
    sessionRuleCount,
    rulesMeta,
    datasetRevision: dataset.revision,
    datasetUpdatedAt: dataset.updatedAt,
    psl: pslStatus(),
  };
}

export interface FeedsOverview {
  readonly states: readonly ProviderState[];
  readonly revision: number;
  readonly updatedAt: number;
}

/** Runs a feed refresh and rebuilds the rule set afterwards. */
export async function refreshAndRebuild(force: boolean): Promise<FeedsOverview> {
  const outcome = await updateFeeds({ force });
  if (!outcome.previousDatasetPreserved) {
    await ensureRules(true);
  }
  const dataset = await loadDataset();
  return { states: dataset.states, revision: dataset.revision, updatedAt: dataset.updatedAt };
}

/** Dry-run the compiler so Diagnostics can show the quota plan. */
export async function previewRulePlan(): Promise<ReturnType<typeof buildRules>> {
  const [settings, allowlist, dataset] = await Promise.all([getSettings(), getAllowlist(), loadDataset()]);
  const assembled = assembleDatasets(dataset);
  return buildRules({ settings, datasets: assembled.datasets, allowlist });
}
