/**
 * Thin, defensive wrapper over `chrome.declarativeNetRequest`.
 *
 * Responsibilities: capability detection, quota reporting, atomic rule swaps and
 * translating API errors into actionable diagnostics instead of silent failures.
 *
 * NO MATCHED-RULE FEEDBACK, DELIBERATELY
 * -------------------------------------
 * `onRuleMatchedDebug` and `getMatchedRules()` require the
 * `declarativeNetRequestFeedback` permission, which Chrome documents as:
 *
 *   "Enables debugging features for unpacked extensions, specifically
 *    getMatchedRules() and onRuleMatchedDebug."
 *
 * and the event itself as "only available for unpacked extensions ... as this is
 * intended to be used for debugging purposes only".
 *
 * A published extension therefore has no matched-rule feed at all. This wrapper
 * used to expose one, which produced two real production faults: every block
 * counter read zero after a store install, and the user saw a raw browser error
 * page instead of our explanation. Both now come from `webNavigation`; see
 * `src/background/observation.ts`.
 *
 * Nothing in this file may re-introduce a dependency on that permission.
 */
import { compileAllowRule, readRuntimeLimits, type CompiledRule, type RuntimeLimits } from '../blocking/compiler';

export interface DnrCapabilities {
  readonly available: boolean;
  readonly dynamicRules: boolean;
  readonly sessionRules: boolean;
  readonly limits: RuntimeLimits;
  readonly maxRuleId: number;
}

let caps: DnrCapabilities | null = null;

export function dnrCapabilities(): DnrCapabilities {
  if (caps) return caps;
  const dnr = chrome.declarativeNetRequest as unknown as Record<string, unknown> | undefined;
  const available = typeof dnr !== 'undefined' && typeof chrome.declarativeNetRequest?.updateDynamicRules === 'function';
  const limits = readRuntimeLimits();
  caps = {
    available,
    dynamicRules: available,
    sessionRules: available && typeof chrome.declarativeNetRequest.updateSessionRules === 'function',
    limits,
    maxRuleId: Number.MAX_SAFE_INTEGER,
  };
  return caps;
}

export async function getDynamicRuleCount(): Promise<number> {
  if (!dnrCapabilities().dynamicRules) return 0;
  try {
    const rules = await chrome.declarativeNetRequest.getDynamicRules();
    return rules.length;
  } catch {
    return 0;
  }
}

export async function getEnabledStaticRuleCount(): Promise<number | null> {
  try {
    const count = await chrome.declarativeNetRequest.getAvailableStaticRuleCount();
    return count;
  } catch {
    return null;
  }
}

export interface SwapResult {
  readonly ok: boolean;
  readonly removed: number;
  readonly added: number;
  readonly error: string | null;
  /** Rules the browser rejected. */
  readonly rejected: readonly { id: number; reason: string }[];
}

/**
 * Atomically removes every rule we own and installs `next`.
 *
 * `updateDynamicRules` resolves to void, so the applied count is derived by
 * re-reading the engine rather than trusting a return value. The previous rule
 * set is removed in the SAME call, which makes the swap atomic: the browser
 * either applies the whole batch or rejects it without leaving a partial state.
 */
export async function swapDynamicRules(next: readonly CompiledRule[]): Promise<SwapResult> {
  if (!dnrCapabilities().dynamicRules) {
    return { ok: false, removed: 0, added: 0, error: 'dnr_unavailable', rejected: [] };
  }
  try {
    const current = await chrome.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = current.map((r) => r.id);

    // De-duplicate ids defensively: the API rejects the whole batch otherwise.
    const seen = new Set<number>();
    const addRules: chrome.declarativeNetRequest.Rule[] = [];
    const rejected: { id: number; reason: string }[] = [];
    for (const rule of next) {
      if (seen.has(rule.id)) {
        rejected.push({ id: rule.id, reason: 'duplicate_id' });
        continue;
      }
      seen.add(rule.id);
      // `providerId` is our own provenance marker, not a DNR field. It must be
      // stripped here: passing an unknown key makes the browser reject the rule,
      // and the whole atomic swap with it.
      const { providerId: _provenance, ...installable } = rule;
      void _provenance;
      addRules.push(installable as chrome.declarativeNetRequest.Rule);
    }

    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });

    const applied = await chrome.declarativeNetRequest.getDynamicRules();
    return { ok: true, removed: removeRuleIds.length, added: applied.length, error: null, rejected };
  } catch (error) {
    return { ok: false, removed: 0, added: 0, error: describeError(error), rejected: [] };
  }
}

/** Installs allowlist overrides as SESSION rules. */
export async function syncAllowlistRules(
  domains: readonly { domain: string; scope: 'all' | 'threats' | 'privacy' }[],
  baseId: number,
): Promise<SwapResult> {
  if (!dnrCapabilities().sessionRules) {
    return { ok: false, removed: 0, added: 0, error: 'session_rules_unavailable', rejected: [] };
  }
  const rejected: { id: number; reason: string }[] = [];
  const addRules: chrome.declarativeNetRequest.Rule[] = [];
  let id = baseId;

  for (const entry of domains) {
    id += 1;
    const rule = compileAllowRule(entry.domain, entry.scope, id);
    if (rule === null) {
      rejected.push({ id, reason: 'invalid_domain' });
      continue;
    }
    addRules.push(rule as chrome.declarativeNetRequest.Rule);
  }

  try {
    const current = await chrome.declarativeNetRequest.getSessionRules();
    const removeRuleIds = current.map((r) => r.id);
    await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules });
    const applied = await chrome.declarativeNetRequest.getSessionRules();
    return { ok: true, removed: removeRuleIds.length, added: applied.length, error: null, rejected };
  } catch (error) {
    return { ok: false, removed: 0, added: 0, error: describeError(error), rejected };
  }
}

export async function getSessionRuleCount(): Promise<number> {
  try {
    return (await chrome.declarativeNetRequest.getSessionRules()).length;
  } catch {
    return 0;
  }
}

function describeError(error: unknown): string {
  if (typeof error === 'string') return error;
  if (error && typeof error === 'object' && 'message' in error) return String((error as { message: unknown }).message);
  return 'unknown_error';
}
