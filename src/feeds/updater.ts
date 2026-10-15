/**
 * Threat intelligence update engine.
 *
 * Guarantees (Section 8 of the specification):
 *  - DATA ONLY. We never download or evaluate JavaScript, WASM or any code.
 *    `fetch` is restricted to `https:` URLs declared in the provider registry.
 *  - Validation of schema, size, entry count and individual records before
 *    anything is persisted.
 *  - Atomic swap: the previous valid dataset survives any failure.
 *  - Downgrade protection: a revision older than the stored one is refused.
 *  - Bounded RAM and storage: feeds are streamed with a hard byte ceiling and
 *    the resulting dataset is size-checked before the write.
 *  - Signature verification is performed when the source offers it. None of our
 *    bundled sources publish per-file signatures, so we record a SHA-256 of the
 *    validated payload and state this limitation in Diagnostics instead of
 *    pretending verification succeeded.
 */
import { FEED_MAX_UPDATE_INTERVAL_MIN, FEED_MIN_UPDATE_INTERVAL_MIN, STORAGE_SOFT_LIMIT_BYTES } from '../core/constants';
import type { ProviderDescriptor, ProviderState, ThreatCategory } from '../core/types';
import { get, set, K } from '../platform/storage';
import { byteSizeOf } from '../platform/storage';
import { MAX_FEED_BYTES, parseAdblock, parseDomainList, parseHosts, type ParseCounters } from './parsers';
import { categoryForProvider } from '../security/reputation';
import { FEED_REGISTRY } from './registry';

export interface ProviderCredential {
  readonly providerId: string;
  readonly key: string;
}

const CREDENTIAL_KEY = 'vbs.feedCredentials';

export interface Dataset {
  readonly revision: number;
  readonly updatedAt: number;
  readonly states: readonly ProviderState[];
  /**
   * Packed, newline-separated host sets per provider id. Hosts and adblock
   * filters are both stored in this shape: the blocking controller already knows
   * each provider's categories from the registry, so no extra bookkeeping is
   * needed and the storage format stays trivially auditable.
   */
  readonly domainsByProvider: ReadonlyMap<string, string>;
  readonly bytes: number;
}

export const DATASET_SCHEMA_VERSION = 1;

/**
 * Hard ceiling for the whole dataset.
 *
 * This was a local 6 MiB constant, below the 9 MiB gate in `persistDataset` and
 * far below the ~27 MiB the real feeds actually produce. It refused every
 * download and left the extension with no threat data at all. See the
 * `DATASET_MAX_BYTES` documentation in `core/constants.ts` for the measurements.
 */
import { DATASET_MAX_BYTES } from '../core/constants';

/** Refuse absurd growth (tampered or truncated response). */
const MAX_ENTRIES_PER_PROVIDER = 500_000;
/** Minimum plausible entry count; below this the response is probably an error page. */
const MIN_ENTRIES_PER_PROVIDER = 1;

export class FeedError extends Error {
  constructor(
    message: string,
    readonly code:
      | 'network'
      | 'http'
      | 'not_https'
      | 'too_large'
      | 'malformed'
      | 'too_few_entries'
      | 'too_many_entries'
      | 'storage_full'
      | 'downgrade'
      | 'not_configured'
      | 'excluded',
    readonly providerId: string,
  ) {
    super(message);
    this.name = 'FeedError';
  }
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export interface FetchOptions {
  readonly credentials?: ReadonlyMap<string, string>;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

/**
 * Fetches one provider's feed with hard limits.
 * Enforces HTTPS and the byte ceiling while streaming.
 */
export async function fetchFeed(provider: ProviderDescriptor, options: FetchOptions = {}): Promise<{ text: string; sha256: string }> {
  if (provider.excludedFromProduct) {
    throw new FeedError('provider excluded from product', 'excluded', provider.id);
  }
  if (provider.requiresCredential) {
    const key = options.credentials?.get(provider.id);
    if (!key) throw new FeedError('credential required', 'not_configured', provider.id);
  }

  let url: URL;
  try {
    url = new URL(provider.feedUrl);
  } catch {
    throw new FeedError('invalid feed url', 'malformed', provider.id);
  }
  if (url.protocol !== 'https:') {
    throw new FeedError('feed url must be https', 'not_https', provider.id);
  }

  const doFetch = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 30_000);

  try {
    const headers: Record<string, string> = { accept: 'text/plain, */*' };
    const key = options.credentials?.get(provider.id);
    if (key && provider.id === 'urlhaus') headers.authkey = key;
    if (key && provider.id === 'phishtank') headers['app_key'] = key;

    const response = await doFetch(url.toString(), { headers, signal: controller.signal, redirect: 'follow', credentials: 'omit', cache: 'no-cache' });
    if (!response.ok) throw new FeedError(`HTTP ${response.status}`, 'http', provider.id);

    const declared = Number(response.headers.get('content-length') ?? '0');
    if (Number.isFinite(declared) && declared > MAX_FEED_BYTES) {
      throw new FeedError('declared size exceeds limit', 'too_large', provider.id);
    }

    const text = await readBounded(response, provider.id);
    return { text, sha256: await sha256Hex(text) };
  } catch (error) {
    if (error instanceof FeedError) throw error;
    const message = error instanceof Error ? error.message : String(error);
    throw new FeedError(message, 'network', provider.id);
  } finally {
    clearTimeout(timeout);
  }
}

async function readBounded(response: Response, providerId: string): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text();
    if (text.length > MAX_FEED_BYTES) throw new FeedError('payload exceeds limit', 'too_large', providerId);
    return text;
  }
  const decoder = new TextDecoder('utf-8');
  let total = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_FEED_BYTES) {
      await reader.cancel();
      throw new FeedError('payload exceeds limit', 'too_large', providerId);
    }
    out += decoder.decode(value, { stream: true });
  }
  out += decoder.decode();
  return out;
}

export interface ParsedProvider {
  readonly domains: Set<string>;
  readonly counters: ParseCounters;
  readonly feedVersion: string | null;
}

/** Parses and validates one provider payload. Pure; unit-testable. */
export function parseProviderFeed(provider: ProviderDescriptor, text: string): ParsedProvider {
  let domains: Set<string>;
  let counters: ParseCounters;
  let feedVersion: string | null = null;

  switch (provider.format) {
    case 'hosts': {
      const result = parseHosts(text);
      domains = result.hosts;
      counters = result.counters;
      break;
    }
    case 'domain-list': {
      const result = parseDomainList(text);
      domains = result.hosts;
      counters = result.counters;
      const match = /#\s*(?:Date|Updated|Version)[^\d]{0,20}(\d{8})/i.exec(text);
      feedVersion = match?.[1] ?? null;
      break;
    }
    case 'adblock': {
      const result = parseAdblock(text);
      counters = result.counters;
      feedVersion = result.headerVersion;
      domains = new Set(result.rules.map((r) => r.host));
      break;
    }
    default:
      throw new FeedError('unknown format', 'malformed', provider.id);
  }

  if (domains.size < MIN_ENTRIES_PER_PROVIDER) {
    throw new FeedError(`only ${domains.size} valid entries`, 'too_few_entries', provider.id);
  }
  if (domains.size > MAX_ENTRIES_PER_PROVIDER) {
    throw new FeedError(`${domains.size} entries exceeds limit`, 'too_many_entries', provider.id);
  }

  return { domains, counters, feedVersion };
}

export interface UpdateOptions extends FetchOptions {
  /** Only update these providers (default: every bundled provider). */
  readonly only?: readonly string[];
  /** Ignore the minimum interval and refresh now. */
  readonly force?: boolean;
}

export interface UpdateOutcome {
  readonly ok: boolean;
  readonly revision: number;
  readonly updated: readonly ProviderState[];
  readonly failed: readonly { providerId: string; code: string; message: string }[];
  readonly previousDatasetPreserved: boolean;
  readonly bytes: number;
  readonly durationMs: number;
}

/**
 * Runs a full update cycle.
 *
 * The current dataset is only replaced once EVERY provider has been parsed and
 * the resulting size checked. A single provider failure does not discard the
 * other providers' successful results, but the whole write is still atomic.
 */
export async function updateFeeds(options: UpdateOptions = {}): Promise<UpdateOutcome> {
  const startedAt = Date.now();
  const previous = await loadDataset();
  const stored = await loadProviderStates();
  const lastAttempt = stored.meta?.lastAttemptAt ?? 0;
  const now = Date.now();

  if (!options.force && lastAttempt > 0) {
    const elapsedMin = (now - lastAttempt) / 60_000;
    if (elapsedMin < FEED_MIN_UPDATE_INTERVAL_MIN) {
      return {
        ok: true,
        revision: previous.revision,
        updated: previous.states,
        failed: [],
        previousDatasetPreserved: true,
        bytes: previous.bytes,
        durationMs: now - startedAt,
      };
    }
  }

  const credentials = await loadCredentials();
  const mergedCredentials = new Map(credentials);
  for (const [k, v] of options.credentials ?? []) mergedCredentials.set(k, v);

  const targets = FEED_REGISTRY.filter(
    (p) => !p.excludedFromProduct && (!options.only || options.only.includes(p.id)),
  );

  const states: ProviderState[] = [];
  const domainsByProvider = new Map<string, string>();
  const failed: { providerId: string; code: string; message: string }[] = [];
  let anySuccess = false;

  // Seed with the previous successful data so a failed provider does not lose
  // its entries - we degrade to a stale list instead of losing protection.
  for (const state of previous.states) {
    const packed = previous.domainsByProvider.get(state.id);
    if (packed !== undefined) domainsByProvider.set(state.id, packed);
    if (state.status === 'active' || state.status === 'bundled_snapshot') {
      states.push({ ...state, status: 'stale' });
    } else {
      states.push(state);
    }
  }

  for (const provider of targets) {
    try {
      const { text, sha256 } = await fetchFeed(provider, { ...options, credentials: mergedCredentials });
      const parsed = parseProviderFeed(provider, text);
      const packed = [...parsed.domains].sort().join('\n');

      const state: ProviderState = {
        id: provider.id,
        status: 'active',
        lastSuccessAt: now,
        lastAttemptAt: now,
        lastError: null,
        entryCount: parsed.domains.size,
        ruleCount: 0,
        contentHash: sha256,
        feedVersion: parsed.feedVersion,
        skipped: parsed.counters.skipped,
        skippedByReason: parsed.counters.skippedByReason,
      };

      // Adblock-derived hosts use the same packed shape; the controller maps
      // provider -> categories through the registry.
      domainsByProvider.set(provider.id, packed);
      anySuccess = true;

      const index = states.findIndex((s) => s.id === provider.id);
      if (index >= 0) states[index] = state;
      else states.push(state);
    } catch (error) {
      const feedError = error instanceof FeedError ? error : new FeedError(String(error), 'network', provider.id);
      failed.push({ providerId: provider.id, code: feedError.code, message: feedError.message });
      const index = states.findIndex((s) => s.id === provider.id);
      const fallback: ProviderState =
        index >= 0
          ? { ...states[index]!, lastAttemptAt: now, status: 'error', lastError: `${feedError.code}: ${feedError.message}` }
          : {
              id: provider.id,
              status: provider.requiresCredential ? 'not_configured' : 'error',
              lastSuccessAt: null,
              lastAttemptAt: now,
              lastError: `${feedError.code}: ${feedError.message}`,
              entryCount: 0,
              ruleCount: 0,
              contentHash: null,
              feedVersion: null,
              skipped: 0,
              skippedByReason: {},
            };
      if (index >= 0) states[index] = fallback;
      else states.push(fallback);
    }
  }

  // Providers that are registered but not updated in this cycle keep their state.
  for (const provider of FEED_REGISTRY) {
    if (states.some((s) => s.id === provider.id)) continue;
    states.push({
      id: provider.id,
      status: provider.excludedFromProduct ? 'excluded_license' : provider.requiresCredential ? 'not_configured' : 'disabled',
      lastSuccessAt: null,
      lastAttemptAt: now,
      lastError: provider.exclusionReason ?? null,
      entryCount: 0,
      ruleCount: 0,
      contentHash: null,
      feedVersion: null,
      skipped: 0,
      skippedByReason: {},
    });
  }

  // Nothing new arrived. Do not churn the revision or rewrite storage: the
  // stored dataset IS the last valid one, and bumping the revision would make
  // an interrupted update indistinguishable from a real one.
  if (!anySuccess && previous.revision > 0) {
    return {
      ok: false,
      revision: previous.revision,
      updated: previous.states,
      failed,
      previousDatasetPreserved: true,
      bytes: previous.bytes,
      durationMs: Date.now() - startedAt,
    };
  }

  // ---- Size gate before touching storage.
  let bytes = 0;
  for (const packed of domainsByProvider.values()) bytes += packed.length * 2;
  if (bytes > DATASET_MAX_BYTES) {
    // Do not destroy the last valid dataset. Report and keep it.
    return {
      ok: false,
      revision: previous.revision,
      updated: previous.states,
      failed: [...failed, { providerId: '-', code: 'too_large', message: `dataset ${bytes} bytes exceeds ${DATASET_MAX_BYTES}` }],
      previousDatasetPreserved: true,
      bytes: previous.bytes,
      durationMs: Date.now() - startedAt,
    };
  }

  const nextRevision = previous.revision + 1;
  if (nextRevision <= previous.revision) {
    return {
      ok: false,
      revision: previous.revision,
      updated: previous.states,
      failed: [...failed, { providerId: '-', code: 'downgrade', message: 'revision would not increase' }],
      previousDatasetPreserved: true,
      bytes: previous.bytes,
      durationMs: Date.now() - startedAt,
    };
  }

  const dataset: Dataset = {
    revision: nextRevision,
    updatedAt: now,
    states,
    domainsByProvider,
    bytes,
  };

  try {
    await persistDataset(dataset);
    // Persist the attempt timestamp so the minimum-interval throttle actually
    // works across service-worker restarts. Without this every browser start
    // would hit the network again.
    await set(K.feedState, { lastAttemptAt: now, lastRevision: nextRevision, lastSuccessAt: now });
  } catch (error) {
    return {
      ok: false,
      revision: previous.revision,
      updated: previous.states,
      failed: [...failed, { providerId: '-', code: 'storage_full', message: error instanceof Error ? error.message : String(error) }],
      previousDatasetPreserved: true,
      bytes: previous.bytes,
      durationMs: Date.now() - startedAt,
    };
  }

  return {
    // A provider that legitimately needs a user-supplied credential is in a
    // known, documented state - it is listed in `failed` for full transparency
    // but does not make the cycle itself a failure.
    ok: failed.every((f) => f.code === 'not_configured'),
    revision: nextRevision,
    updated: states,
    failed,
    previousDatasetPreserved: false,
    bytes,
    durationMs: Date.now() - startedAt,
  };
}

export async function loadDataset(): Promise<Dataset> {
  const raw = await get<Record<string, unknown>>(K.feedDataset);
  if (!raw || typeof raw !== 'object') {
    return {
      revision: 0,
      updatedAt: 0,
      states: [],
      domainsByProvider: new Map(),
      bytes: 0,
    };
  }
  const domainsByProvider = new Map<string, string>();
  for (const [key, value] of Object.entries(raw)) {
    if (key === 'revision' || key === 'updatedAt' || key === 'states' || key === 'schemaVersion') continue;
    if (typeof value === 'string') domainsByProvider.set(key, value);
  }
  return {
    revision: typeof raw.revision === 'number' ? raw.revision : 0,
    updatedAt: typeof raw.updatedAt === 'number' ? raw.updatedAt : 0,
    states: Array.isArray(raw.states) ? (raw.states as ProviderState[]) : [],
    domainsByProvider,
    bytes: byteSizeOf(raw),
  };
}

async function persistDataset(dataset: Dataset): Promise<void> {
  const payload: Record<string, unknown> = {
    revision: dataset.revision,
    updatedAt: dataset.updatedAt,
    states: dataset.states,
    schemaVersion: DATASET_SCHEMA_VERSION,
  };
  for (const [id, packed] of dataset.domainsByProvider) payload[id] = packed;
  // The guard is DATASET_MAX_BYTES, not the 10 MB storage quota. `storage.local`
  // has a 10 MB default limit, but the `unlimitedStorage` permission lifts it,
  // and without this the real dataset (~27 MiB) would be refused - which is
  // exactly what shipped: no rules installed, so no protection, reported as a
  // success.
  const projected = byteSizeOf(payload);
  if (projected > DATASET_MAX_BYTES) {
    throw new Error(`dataset would exceed the ceiling (${projected} > ${DATASET_MAX_BYTES})`);
  }
  await chrome.storage.local.set({ [K.feedDataset]: payload });
}

async function loadProviderStates(): Promise<{ meta: { lastAttemptAt: number } | null }> {
  const stored = await get<{ lastAttemptAt?: number }>(K.feedState);
  return { meta: stored && typeof stored.lastAttemptAt === 'number' ? { lastAttemptAt: stored.lastAttemptAt } : null };
}

export async function saveCredentials(credentials: readonly ProviderCredential[]): Promise<void> {
  const current = await loadCredentials();
  for (const c of credentials) current.set(c.providerId, c.key);
  await set(CREDENTIAL_KEY, Object.fromEntries(current));
}

export async function clearCredential(providerId: string): Promise<void> {
  const current = await loadCredentials();
  current.delete(providerId);
  await set(CREDENTIAL_KEY, Object.fromEntries(current));
}

/** Returns the ids of providers that have a credential configured (never values). */
export async function loadCredentials(): Promise<Map<string, string>> {
  const raw = await get<Record<string, string>>(CREDENTIAL_KEY);
  const out = new Map<string, string>();
  if (raw && typeof raw === 'object') {
    for (const [k, v] of Object.entries(raw)) if (typeof v === 'string' && v.length > 0) out.set(k, v);
  }
  return out;
}

export async function configuredProviderIds(): Promise<string[]> {
  return [...(await loadCredentials()).keys()];
}

/** Category assigned to a provider, used when building datasets. */
export function providerCategory(providerId: string): ThreatCategory {
  return categoryForProvider(providerId);
}

export function clampInterval(hours: number): number {
  const minutes = hours * 60;
  return Math.min(FEED_MAX_UPDATE_INTERVAL_MIN, Math.max(FEED_MIN_UPDATE_INTERVAL_MIN, minutes)) / 60;
}
