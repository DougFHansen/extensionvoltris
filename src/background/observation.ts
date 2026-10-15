/**
 * Production block observation.
 *
 * WHY THIS MODULE EXISTS
 * ----------------------
 * The first version of VOLTRIS counted blocks through
 * `declarativeNetRequest.onRuleMatchedDebug`. That was wrong for a published
 * extension. Chrome documents it as:
 *
 *   "Fired when a rule is matched with a request. Only available for unpacked
 *    extensions with the 'declarativeNetRequestFeedback' permission as this is
 *    intended to be used for debugging purposes only."
 *
 * and `declarativeNetRequestFeedback` itself as:
 *
 *   "Enables debugging features for unpacked extensions, specifically
 *    getMatchedRules() and onRuleMatchedDebug."
 *
 * So in a store install the counters would read zero AND the explanatory block
 * page would never appear. Both are fixed here using `webNavigation`, which is
 * available to published extensions.
 *
 * HOW IT WORKS
 * ------------
 * 1. `chrome.webNavigation.onErrorOccurred` fires for a navigation that failed.
 * 2. We keep only main-frame failures (`frameId === 0`) with
 *    `net::ERR_BLOCKED_BY_CLIENT`.
 * 3. We VERIFY the block was ours by resolving the destination against our own
 *    local threat dataset and confirming the matching category is enabled. If
 *    another extension blocked the same URL, we do not claim the block.
 * 4. We then record the observation and drive the tab to our own page.
 *
 * WHAT THIS CANNOT COUNT
 * ---------------------
 * Sub-resource requests (images, scripts, trackers, fonts). There is no
 * production API that reports them. We say so in the interface instead of
 * estimating. See `METRIC_CAPABILITIES` in `src/core/types.ts`.
 */
import type { ThreatCategory } from '../core/types';
import { recordBlockedNavigation } from '../data/stats';
import { recordHistory } from '../data/history';
import { getSettings } from '../data/settings';
import { lookupThreat } from '../security/reputation';
import { parseTarget } from '../security/url-normalize';
import { resolvePublicSuffix } from '../security/psl';
import { handleMatchedNavigation } from './interstitial';

/** The navigation error Chrome reports when a DNR rule blocks a request. */
const BLOCKED_BY_CLIENT = 'net::ERR_BLOCKED_BY_CLIENT';

export interface ObservationDiagnostics {
  readonly apiAvailable: boolean;
  readonly observed: number;
  readonly rejectedNotOurs: number;
  readonly lastError: string | null;
}

/** Mutable backing store; the exported interface stays readonly. */
interface MutableObservation {
  apiAvailable: boolean;
  observed: number;
  rejectedNotOurs: number;
  lastError: string | null;
}

const diagnostics: MutableObservation = {
  apiAvailable: false,
  observed: 0,
  rejectedNotOurs: 0,
  lastError: null,
};

export function observationStatus(): ObservationDiagnostics {
  return { ...diagnostics };
}

let historyEnabled = true;

export async function configureObservationPreference(): Promise<void> {
  historyEnabled = (await getSettings()).storeHistory;
}

/**
 * Installs the observer. Safe to call once at service-worker start.
 * Returns whether the API was usable.
 */
export function installBlockObservation(): boolean {
  if (typeof chrome.webNavigation?.onErrorOccurred?.addListener !== 'function') {
    diagnostics.apiAvailable = false;
    diagnostics.lastError = 'webNavigation.onErrorOccurred unavailable';
    return false;
  }

  chrome.webNavigation.onErrorOccurred.addListener((details) => {
    void handleNavigationError(details);
  });

  diagnostics.apiAvailable = true;
  return true;
}

async function handleNavigationError(details: chrome.webNavigation.WebNavigationFramedErrorCallbackDetails): Promise<void> {
  try {
    // 1. Main frame only. Sub-frame and sub-resource failures are not
    //    navigations and are not counted (see the module docstring).
    if (details.frameId !== 0) return;

    // 2. Only a client-side block. DNS failures, TLS errors and user-initiated
    //    cancellations are somebody else's problem and must not inflate our
    //    numbers.
    if (details.error !== BLOCKED_BY_CLIENT) return;

    if (details.tabId < 0) return;

    // 3. Verify it was OUR rule, not another extension's.
    const attribution = await attributeBlock(details.url);
    if (attribution === null) {
      diagnostics.rejectedNotOurs += 1;
      return;
    }

    const settings = await getSettings();
    if (!settings.protectionEnabled) return;

    diagnostics.observed += 1;

    const domain = attribution.registrableDomain ?? attribution.hostname;
    recordBlockedNavigation({ category: attribution.category, domain, at: Date.now() });

    if (historyEnabled) {
      await recordHistory({
        kind: 'threat_blocked',
        domain,
        category: attribution.category,
        providerId: attribution.providerId,
        url: details.url,
        storeFullUrls: settings.storeFullUrls,
      });
    }

    // 4. Explain the block instead of leaving a raw browser error page.
    await handleMatchedNavigation({
      url: details.url,
      tabId: details.tabId,
      category: attribution.category,
      providerId: attribution.providerId,
      matchedDomain: attribution.matchedDomain,
    });
  } catch (error) {
    // An observer must never break the browser's navigation pipeline.
    diagnostics.lastError = error instanceof Error ? error.message : String(error);
  }
}

interface Attribution {
  readonly category: ThreatCategory;
  readonly providerId: string;
  readonly matchedDomain: string;
  readonly hostname: string;
  readonly registrableDomain: string | null;
}

/**
 * Decides whether a blocked URL was blocked by one of OUR rules.
 *
 * A destination is only claimed when it is present in a local threat dataset
 * whose category is currently enabled. Anything else returns null, which means
 * "somebody else blocked this" - we neither count it nor claim it in the UI.
 */
async function attributeBlock(url: string): Promise<Attribution | null> {
  const parsed = parseTarget(url, resolvePublicSuffix);
  if (!parsed.hostname) return null;

  const threat = await lookupThreat(parsed.hostname, parsed.registrableDomain);
  if (!threat) return null;

  const settings = await getSettings();
  if (!isCategoryEnabled(settings, threat.record.category)) return null;

  return {
    category: threat.record.category,
    providerId: threat.record.providerId,
    matchedDomain: threat.matchedDomain,
    hostname: parsed.hostname,
    registrableDomain: parsed.registrableDomain,
  };
}

function isCategoryEnabled(settings: Awaited<ReturnType<typeof getSettings>>, category: ThreatCategory): boolean {
  switch (category) {
    case 'phishing':
      return settings.blockPhishing;
    case 'malware':
    case 'malware_distribution':
      return settings.blockMalware || settings.blockMalwareDistribution;
    case 'scam':
      return settings.blockScam;
    // Privacy categories never block main_frame, so they cannot reach here.
    default:
      return false;
  }
}
