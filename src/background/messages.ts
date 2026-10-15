/**
 * Message router for the service worker.
 *
 * This is the trust boundary. Every inbound message is parsed and validated
 * before any handler runs. Content-script messages are treated as hostile page
 * data: they are length-bounded, type-checked and never allowed to trigger
 * network access or privileged operations.
 */
import type { AnalysisResult, HistoryEvent, ProviderDescriptor, ProviderState, Settings, ThreatCategory } from '../core/types';
import { METRIC_CAPABILITIES } from '../core/types';
import {
  err,
  ok,
  parseEnvelope,
  validatePayload,
  type MessageType,
  type Response,
} from '../platform/messages';
import { getSettings, updateSettings, resetSettings, type SettingsPatch } from '../data/settings';
import {
  addToAllowlist,
  clearAllowlist,
  getAllowlist,
  removeFromAllowlist,
  setEntryEnabled,
  setEntryScope,
} from '../data/allowlist';
import { clearHistory, deleteHistoryEvent, getHistory, recordHistory } from '../data/history';
import { clearData, usage, type ClearScope } from '../platform/storage';
import { K } from '../platform/storage';
import { getStats, resetStats } from '../data/stats';
import { analyzeCurrentTab, analyzeWithContext } from './navigation';
import { configureObservationPreference, observationStatus } from './observation';
import { DOWNLOAD_LISTS } from './downloads';
import { ensureRules, getProtectionState, getRulesMeta, previewRulePlan, refreshAndRebuild } from './rules';
import { runUpdateCycle } from './alarms';
import { configuredProviderIds, loadDataset, saveCredentials, clearCredential } from '../feeds/updater';
import { FEED_REGISTRY, providerById } from '../feeds/registry';
import { registerScarcityScan } from '../scam/content-bridge';
import { getBlockRecord } from './interstitial';
import { listenerStatus } from './listener-registry';
import { analyzePageSignals } from '../scam/signals';
import { pslStatus } from '../security/psl';
import { primeSettings } from '../data/settings';
import { updateSettings as patchSettings } from '../data/settings';
import { invalidateAllCaches } from '../data/caches';
import { syncAllowlist } from '../blocking/controller';
import { flushPendingWrites } from '../data/caches';

export interface StatusResponse {
  readonly settings: Settings;
  readonly currentTab: { id: number; url: string | null; analysis: AnalysisResult | null } | null;
  readonly stats: Awaited<ReturnType<typeof getStats>>;
  readonly protection: Awaited<ReturnType<typeof getProtectionState>>;
  readonly allowlistSize: number;
}

export type SenderKind = 'extension' | 'content' | 'unknown';

/**
 * Classifies who sent a message.
 *
 * - `extension`: an extension page (popup, dashboard, options, blocked page),
 *   whether it lives in a tab or in the action popup. Trusted for all types.
 * - `content`: our content script injected into a web page. Trusted ONLY for the
 *   two explicitly whitelisted message types, because the page it runs on is
 *   hostile by definition.
 * - `unknown`: anything else. Rejected.
 */
export function classifySender(sender: chrome.runtime.MessageSender): SenderKind {
  const ourId = typeof chrome !== 'undefined' && chrome.runtime?.id ? chrome.runtime.id : null;
  if (ourId === null || sender.id !== ourId) return 'unknown';

  const url = typeof sender.url === 'string' ? sender.url : '';
  const origin = chrome.runtime.getURL('');

  if (url.startsWith(origin)) return 'extension';

  // A content script reports the URL of the page it was injected into.
  if (/^https?:\/\//i.test(url)) return 'content';

  // No URL (some internal sends): fall back to the tab heuristic.
  return sender.tab === undefined ? 'extension' : 'unknown';
}

export async function handleMessage(): Promise<void> {
  chrome.runtime.onMessage.addListener((raw, sender, sendResponse) => {
    const envelope = parseEnvelope(raw);
    if (envelope === null) {
      sendResponse(err('invalid envelope', 'error_invalid_message'));
      return false;
    }
    const payload = validatePayload(envelope.t, envelope.p);
    if (payload === null) {
      sendResponse(err('invalid payload', 'error_invalid_payload'));
      return false;
    }

    // Sender classification is a trust boundary, so it has to be precise.
    //
    // `sender.tab !== undefined` is NOT a reliable content-script test: opening
    // the popup, dashboard or options page in a TAB also sets `sender.tab`.
    // Those are first-party extension pages and must be allowed to call
    // everything. Content scripts are identified by their sender URL being the
    // PAGE url rather than our own extension origin.
    const senderKind = classifySender(sender);
    if (senderKind === 'unknown') {
      sendResponse(err('unknown sender', 'error_forbidden_sender'));
      return false;
    }
    if (senderKind === 'content' && envelope.t !== 'content.scamSignals' && envelope.t !== 'content.linkInspect') {
      sendResponse(err('forbidden sender', 'error_forbidden_sender'));
      return false;
    }

    void dispatch(envelope.t, payload, sender)
      .then((response) => sendResponse(response))
      .catch((error: unknown) => {
        sendResponse(err(error instanceof Error ? error.message : 'unknown', 'error_generic', envelope.id));
      });

    return true; // async response
  });
}

async function dispatch(t: MessageType, p: unknown, sender: chrome.runtime.MessageSender): Promise<Response> {
  switch (t) {
    case 'get.status':
      return ok(await buildStatus());
    case 'get.analysis': {
      const { url } = p as { url: string };
      const result = await analyzeWithContext(url);
      return ok({ url, result });
    }
    case 'get.dashboard':
      return ok(await buildDashboard());
    case 'settings.get':
      return ok(await getSettings());
    case 'settings.patch': {
      const next = await patchSettings(p as SettingsPatch);
      await onSettingsChanged();
      return ok(next);
    }
    case 'settings.reset': {
      const next = await resetSettings();
      await onSettingsChanged();
      return ok(next);
    }
    case 'allowlist.list':
      return ok(await getAllowlist());
    case 'allowlist.add': {
      const { domain, scope, from } = p as { domain: string; scope: 'all' | 'threats' | 'privacy'; from?: string };
      const entry = await addToAllowlist(domain, scope, from);
      if (!entry) return err('invalid domain', 'error_invalid_domain');
      await syncAllowlist(await getAllowlist());
      await recordHistory({ kind: 'allowlist_changed', domain: entry.domain, storeFullUrls: false });
      return ok(entry);
    }
    case 'allowlist.remove': {
      const { domain } = p as { domain: string };
      const removed = await removeFromAllowlist(domain);
      if (!removed) return err('not found', 'error_not_found');
      await syncAllowlist(await getAllowlist());
      return ok({ removed });
    }
    case 'allowlist.toggle': {
      const { domain, enabled } = p as { domain: string; enabled?: boolean };
      const current = (await getAllowlist()).find((e) => e.domain === domain);
      if (!current) return err('not found', 'error_not_found');
      const next = enabled === undefined ? !current.enabled : enabled;
      const changed = await setEntryEnabled(domain, next);
      if (!changed) return err('not found', 'error_not_found');
      await syncAllowlist(await getAllowlist());
      return ok({ domain, enabled: next });
    }
    case 'allowlist.scope': {
      const { domain, scope } = p as { domain: string; scope: 'all' | 'threats' | 'privacy' };
      const changed = await setEntryScope(domain, scope);
      if (!changed) return err('not found', 'error_not_found');
      await syncAllowlist(await getAllowlist());
      return ok({ domain, scope });
    }
    case 'history.list':
      return ok(await getHistory());
    case 'history.clear':
      await clearHistory();
      return ok({ cleared: true });
    case 'history.delete': {
      const { id } = p as { id: string };
      await deleteHistoryEvent(id);
      return ok({ deleted: true });
    }
    case 'feeds.refresh': {
      await runUpdateCycle('manual');
      const dataset = await loadDataset();
      return ok({ states: dataset.states, revision: dataset.revision, updatedAt: dataset.updatedAt });
    }
    case 'feeds.state': {
      const [dataset, configured] = await Promise.all([loadDataset(), configuredProviderIds()]);
      return ok({ states: dataset.states, revision: dataset.revision, updatedAt: dataset.updatedAt, configured });
    }
    case 'feeds.credential': {
      const { providerId, key } = p as { providerId: string; key: string };
      if (!FEED_REGISTRY.some((f) => f.requiresCredential && f.id === providerId)) {
        return err('provider does not accept credentials', 'error_not_configured');
      }
      if (key.length === 0) {
        await clearCredential(providerId);
        return ok({ providerId, cleared: true });
      }
      await saveCredentials([{ providerId, key }]);
      return ok({ providerId, saved: true });
    }
    case 'rules.diagnostics':
      return ok(await buildDiagnostics());
    case 'data.clear': {
      const scope = sanitizeClearScope(p);
      const removed = await clearData(scope);
      invalidateAllCaches();
      await primeSettingsOrDefaults();
      await resetStats();
      return ok({ removed });
    }
    case 'data.usage':
      return ok(await usage());
    case 'page.rescan': {
      const { tabId } = p as { tabId: number };
      await registerScarcityScan(tabId);
      return ok({ scanned: true });
    }
    case 'download.lists':
      return ok(DOWNLOAD_LISTS);
    case 'blocked.details':
      return ok(await buildBlockDetails((p as { token: string }).token));
    case 'content.scamSignals': {
      const result = await analyzePageSignals(p as never, sender);
      return ok(result);
    }
    case 'content.linkInspect': {
      const { url } = p as { url: string };
      const result = await analyzeWithContext(url);
      return ok({ url, result });
    }
    default:
      return err('unhandled', 'error_generic');
  }
}

export interface BlockDetails {
  readonly found: boolean;
  readonly url: string | null;
  readonly hostname: string | null;
  readonly category: ThreatCategory | null;
  /** Exact dataset entry that matched, e.g. a parent domain of the host. */
  readonly matchedDomain: string | null;
  readonly blockedAt: number | null;
  readonly analysis: AnalysisResult | null;
  readonly sourceProvider: { id: string; name: string; homepage: string; license: string } | null;
}

/**
 * Resolves the opaque token from the blocked page into a fully explained verdict.
 *
 * The analysis is recomputed HERE, in the service worker, from the recorded URL.
 * The page therefore never has to trust anything that arrived in its query
 * string, and the displayed verdict always reflects the current feed data
 * rather than a snapshot captured at block time.
 */
async function buildBlockDetails(token: string): Promise<BlockDetails> {
  const record = await getBlockRecord(token);
  if (!record) {
    return {
      found: false,
      url: null,
      hostname: null,
      category: null,
      matchedDomain: null,
      blockedAt: null,
      analysis: null,
      sourceProvider: null,
    };
  }

  const analysis = await analyzeWithContext(record.url);
  const source = analysis.sources[0];
  const descriptor = source ? providerById(source.providerId) : undefined;

  return {
    found: true,
    url: record.url,
    hostname: safeHostname(record.url),
    category: record.category,
    matchedDomain: record.matchedDomain,
    blockedAt: record.at,
    analysis,
    sourceProvider:
      source && descriptor
        ? { id: descriptor.id, name: descriptor.name, homepage: descriptor.homepage, license: descriptor.license.name }
        : null,
  };
}

function safeHostname(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function sanitizeClearScope(p: unknown): ClearScope {  const source = (p ?? {}) as Record<string, unknown>;
  const read = (key: keyof ClearScope): boolean => {
    const value = source[key];
    return typeof value === 'boolean' ? value : true;
  };
  return {
    settings: read('settings'),
    statistics: read('statistics'),
    allowlist: read('allowlist'),
    history: read('history'),
    threatData: read('threatData'),
  };
}

async function primeSettingsOrDefaults(): Promise<void> {
  invalidateAllCaches();
  const settings = await getSettings();
  primeSettings(settings);
}

async function onSettingsChanged(): Promise<void> {
  await configureObservationPreference();
  await scheduleAlarmsIfNeeded();
  await ensureRules(true);
  await flushPendingWrites();
}

async function scheduleAlarmsIfNeeded(): Promise<void> {
  const { scheduleAlarms } = await import('./alarms');
  await scheduleAlarms();
}

async function buildStatus(): Promise<StatusResponse> {
  const settings = await getSettings();
  const stats = await getStats();
  const protection = await getProtectionState();
  const allowlist = await getAllowlist();

  let currentTab: StatusResponse['currentTab'] = null;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && typeof tab.id === 'number') {
      const analysis = await analyzeCurrentTab(tab.id);
      currentTab = { id: tab.id, url: analysis.url, analysis: analysis.result };
    }
  } catch {
    currentTab = null;
  }

  return { settings, currentTab, stats, protection, allowlistSize: allowlist.length };
}

export interface DashboardResponse {
  readonly status: StatusResponse;
  readonly allowlist: Awaited<ReturnType<typeof getAllowlist>>;
  readonly history: HistoryEvent[];
  readonly feeds: { states: ProviderState[]; revision: number; updatedAt: number; configured: string[] };
  readonly daily: { day: string; count: number }[];
}

async function buildDashboard(): Promise<DashboardResponse> {
  const [status, allowlist, history, dataset, configured] = await Promise.all([
    buildStatus(),
    getAllowlist(),
    getHistory(),
    loadDataset(),
    configuredProviderIds(),
  ]);
  return {
    status,
    allowlist,
    history,
    feeds: { states: [...dataset.states], revision: dataset.revision, updatedAt: dataset.updatedAt, configured },
    daily: buildDaily(status.stats.blockedByDay),
  };
}

function buildDaily(byDay: Record<string, number>): { day: string; count: number }[] {
  const out: { day: string; count: number }[] = [];
  const now = Date.now();
  for (let i = 13; i >= 0; i -= 1) {
    const day = new Date(now - i * 86_400_000).toISOString().slice(0, 10);
    out.push({ day, count: byDay[day] ?? 0 });
  }
  return out;
}

export interface DiagnosticsResponse {
  readonly protection: Awaited<ReturnType<typeof getProtectionState>>;
  readonly rulesMeta: Awaited<ReturnType<typeof getRulesMeta>>;
  readonly preview: {
    compiled: number;
    droppedForQuota: number;
    rejectedInvalidHost: number;
    duplicatesRemoved: number;
    perCategory: Record<string, number>;
    truncatedCategories: string[];
    quota: { budget: number; datasetBudget: number; perCategory: Record<string, number> };
  };
  readonly permissions: { name: string; present: boolean; justificationKey: string }[];
  readonly storage: Awaited<ReturnType<typeof usage>>;
  readonly psl: ReturnType<typeof pslStatus>;
  readonly registeredProviders: typeof FEED_REGISTRY;
  readonly historyKeys: readonly string[];
  readonly listeners: { registered: readonly string[]; unavailable: readonly string[] };
  readonly observation: ReturnType<typeof observationStatus>;
  readonly metrics: typeof METRIC_CAPABILITIES;
}



const REQUIRED_PERMISSIONS: { name: string; justificationKey: string }[] = [
  { name: 'storage', justificationKey: 'permission_storage' },
  { name: 'alarms', justificationKey: 'permission_alarms' },
  { name: 'declarativeNetRequest', justificationKey: 'permission_dnr' },
  { name: 'webNavigation', justificationKey: 'permission_webnavigation' },
  { name: 'downloads', justificationKey: 'permission_downloads' },
  { name: 'notifications', justificationKey: 'permission_notifications' },
  { name: 'scripting', justificationKey: 'permission_scripting' },
  { name: 'tabs', justificationKey: 'permission_tabs' },
];

async function buildDiagnostics(): Promise<DiagnosticsResponse> {
  const [protection, rulesMeta, preview, storage] = await Promise.all([
    getProtectionState(),
    getRulesMeta(),
    previewRulePlan(),
    usage(),
  ]);

  const granted = new Set<string>();
  try {
    const manifest = chrome.runtime.getManifest();
    for (const entry of manifest.permissions ?? []) granted.add(entry);
  } catch {
    /* manifest unavailable in tests */
  }

  return {
    protection,
    rulesMeta,
    preview: {
      compiled: preview.rules.length,
      droppedForQuota: preview.droppedForQuota,
      rejectedInvalidHost: preview.rejectedInvalidHost,
      duplicatesRemoved: preview.duplicatesRemoved,
      perCategory: preview.installedByCategory,
      truncatedCategories: [...preview.truncatedCategories],
      quota: {
        budget: preview.quota.budget,
        datasetBudget: preview.quota.datasetBudget,
        perCategory: preview.quota.perCategory,
      },
    },
    permissions: REQUIRED_PERMISSIONS.map((p) => ({ ...p, present: granted.has(p.name) })),
    storage,
    psl: pslStatus(),
    registeredProviders: [...FEED_REGISTRY],
    historyKeys: Object.keys(await chrome.storage.local.get(null)),
    listeners: listenerStatus(),
    // PRODUCTION instrumentation. `webNavigation.onErrorOccurred` is available
    // to published extensions, so both the block counters and the explanatory
    // interstitial work in a store install.
    observation: observationStatus(),
    metrics: METRIC_CAPABILITIES,
  };
}
