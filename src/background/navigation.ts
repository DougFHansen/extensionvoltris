/**
 * Tab analysis and the lightweight tab cache.
 *
 * BLOCK ACCOUNTING LIVES ELSEWHERE
 * ---------------------------------
 * This file used to count every matched rule via
 * `declarativeNetRequest.onRuleMatchedDebug`. That API is documented as
 * unpacked-only, so those numbers would have read zero in a published
 * extension. Production block observation now lives in `./observation.ts` and
 * is built on `webNavigation`.
 */
import type { AnalysisResult, RiskVerdict } from '../core/types';
import { recordSuspiciousDetection } from '../data/stats';
import { getSettings } from '../data/settings';
import { allowlistDomainSet, getAllowlist } from '../data/allowlist';
import { analyzeUrl } from '../security/risk';

/**
 * Analyses the active tab when the popup or dashboard asks for it.
 * We do NOT auto-analyse every navigation: that would be a permanent per-page
 * cost. The popup asks, and the content script reports scam signals for the
 * pages it is actually running on.
 */
export async function analyzeCurrentTab(tabId: number): Promise<{ url: string | null; result: AnalysisResult | null }> {
  try {
    const tab = await chrome.tabs.get(tabId);
    const url = typeof tab.url === 'string' ? tab.url : null;
    if (!url) return { url: null, result: null };
    const result = await analyzeWithContext(url);
    if (result.verdict === 'suspicious') recordSuspiciousDetection();
    return { url, result };
  } catch {
    return { url: null, result: null };
  }
}

export async function analyzeWithContext(url: string): Promise<AnalysisResult> {
  const [settings, allowlist] = await Promise.all([getSettings(), getAllowlist()]);
  return analyzeUrl(url, {
    settings,
    allowlisted: allowlistDomainSet(allowlist),
  });
}

/** Lightweight tab cache so the popup can render without re-analysing. */
const tabCache = new Map<number, { url: string; verdict: RiskVerdict; at: number }>();

export function onTabUpdates(): void {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (tabCache.size > 500) tabCache.clear();
    if (changeInfo.status === 'loading') {
      tabCache.delete(tabId);
      return;
    }
    if (changeInfo.status !== 'complete') return;
    const url = typeof tab.url === 'string' ? tab.url : null;
    if (!url) return;
    tabCache.set(tabId, { url, verdict: 'no-threat-found', at: Date.now() });
  });

  chrome.tabs.onRemoved.addListener((tabId) => {
    tabCache.delete(tabId);
  });
}

export function cachedTab(tabId: number): { url: string; verdict: RiskVerdict; at: number } | null {
  return tabCache.get(tabId) ?? null;
}
