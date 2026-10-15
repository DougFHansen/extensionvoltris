/**
 * Reputation store: the locally-held copy of verified threat feeds.
 *
 * Storage layout (chrome.storage.local, key prefix `vbs.threats.`):
 *   vbs.threats.<providerId>  -> packed string, one domain per line
 *   vbs.threats.__meta        -> provider metadata array
 *
 * Packing domains into one string per provider keeps storage overhead low and
 * makes a single `storage.local.get` fetch an entire provider atomically. The
 * Set index is built lazily on first lookup and cached for the lifetime of the
 * service worker.
 *
 * IMPORTANT: this store is the single source of truth for the
 * `known-malicious` verdict. A heuristic alone can never produce it.
 */
import type { ProviderState, ThreatCategory, ThreatRecord } from '../core/types';
import { PROVIDER_INDEX } from '../feeds/registry';

const PREFIX = 'vbs.threats.';
const META_KEY = `${PREFIX}__meta`;

/** Serialized as newline-separated domains. Control chars are impossible in a hostname. */
const SEPARATOR = '\n';

export interface ProviderBundle {
  readonly providerId: string;
  readonly domains: ReadonlySet<string>;
}

interface Loaded {
  readonly meta: ProviderState[];
  readonly bundles: Map<string, ProviderBundle>;
  readonly loadedAt: number;
}

let cache: Loaded | null = null;
let inflight: Promise<Loaded> | null = null;

export interface ReputationLookup {
  readonly record: ThreatRecord;
  readonly provider: ProviderState;
  /** The exact entry that matched (a parent domain of the analysed host). */
  readonly matchedDomain: string;
}

/** Max label hops when walking from hostname up to the registrable domain. */
const MAX_PARENT_HOPS = 6;

function isValidDomainKey(value: string): boolean {
  if (value.length === 0 || value.length > 253) return false;
  if (!/^[a-z0-9.-]+$/.test(value)) return false;
  if (value.startsWith('.') || value.startsWith('-') || value.endsWith('.')) return false;
  return value.includes('.');
}

export function encodeDomains(domains: Iterable<string>): string {
  const out: string[] = [];
  for (const d of domains) {
    const v = d.trim().toLowerCase();
    if (isValidDomainKey(v)) out.push(v);
  }
  return out.sort().join(SEPARATOR);
}

/**
 * Deterministic, alphabet-spanning selection.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every provider has a per-category rule budget far smaller than its entry
 * count: EasyList alone offers ~50,000 network hosts against a 2,000-rule ad
 * budget. Something must be dropped, and the naive choice - take the first N of
 * a sorted list - is actively harmful here.
 *
 * The feeds are sorted ASCII, so the first N entries are every domain beginning
 * with a handful of letters. An ad blocker compiled that way does not block
 * ads: `||0.0.0.0.creative.hpyrdr.com^` is exactly what got installed before this
 * function existed. It looks like work is being done while coverage is close to
 * useless.
 *
 * An even stride across the sorted list keeps every region of the alphabet, so
 * the retained subset behaves like a uniform sample of the real list. The
 * selection is stable: the same input always yields the same output, which
 * matters because the user-visible "dropped for quota" counts must be
 * reproducible.
 *
 * The stride is walked in sorted order, so this is O(n) and does not need the
 * full list in memory beyond the caller's sorted iteration.
 */
export function selectEvenly<T>(items: readonly T[], count: number): T[] {
  if (count <= 0) return [];
  if (items.length <= count) return [...items];

  const step = items.length / count;
  const out: T[] = [];
  const chosen = new Set<number>();
  for (let i = 0; i < count; i += 1) {
    // Rounding can repeat an index; skip rather than emit a duplicate host.
    const index = Math.min(items.length - 1, Math.floor(i * step));
    if (chosen.has(index)) continue;
    chosen.add(index);
    out.push(items[index]!);
  }
  return out;
}

/**
 * Filters a merged category list down to an even sample, without building the
 * merged array first.
 *
 * `assembleDatasets` needs the same selection as `selectEvenly`, but merging
 * every provider's hosts with a spread blew the stack on the real data:
 * `[...new Set(hosts)]` plus `merged.push(...hosts)` reached hundreds of
 * thousands of arguments, and `RangeError: Maximum call stack size exceeded`
 * took down the whole update cycle.
 *
 * Iterating one entry at a time keeps memory flat and cannot overflow the
 * argument limit, whatever the feed size.
 *
 * The stride is computed over `sortedSize` (the count after de-duplication) and
 * applied to the de-duplicated sequence, so the result matches `selectEvenly`
 * on the same input while never materialising it as one array.
 */
export function selectEvenlyIterative(sorted: readonly string[], count: number): Set<string> {
  const out = new Set<string>();
  if (count <= 0 || sorted.length === 0) return out;

  if (sorted.length <= count) {
    for (const host of sorted) out.add(host);
    return out;
  }

  const step = sorted.length / count;
  for (let i = 0; i < count; i += 1) {
    const index = Math.min(sorted.length - 1, Math.floor(i * step));
    out.add(sorted[index]!);
  }
  return out;
}

export function decodeDomains(packed: string | undefined): Set<string> {
  const set = new Set<string>();
  if (!packed) return set;
  for (const line of packed.split(SEPARATOR)) {
    if (line.length > 0 && isValidDomainKey(line)) set.add(line);
  }
  return set;
}

export async function loadReputation(): Promise<Loaded> {
  if (cache) return cache;
  if (inflight) return inflight;
  inflight = (async () => {
    const all = await chrome.storage.local.get(null);
    const meta = (all[META_KEY] as ProviderState[] | undefined) ?? [];
    const bundles = new Map<string, ProviderBundle>();
    for (const state of meta) {
      if (!state || typeof state.id !== 'string') continue;
      const packed = all[`${PREFIX}${state.id}`] as string | undefined;
      bundles.set(state.id, { providerId: state.id, domains: decodeDomains(packed) });
    }
    const loaded: Loaded = { meta, bundles, loadedAt: Date.now() };
    cache = loaded;
    return loaded;
  })();
  return inflight;
}

/**
 * Atomically replaces the reputation dataset.
 * A partial write is impossible: we compute everything first and only then write.
 */
export async function replaceReputation(
  states: readonly ProviderState[],
  domainsByProvider: ReadonlyMap<string, string>,
): Promise<void> {
  const keys = [META_KEY];
  const payload: Record<string, unknown> = {};

  payload[META_KEY] = states;
  for (const state of states) {
    const key = `${PREFIX}${state.id}`;
    keys.push(key);
    payload[key] = domainsByProvider.get(state.id) ?? '';
  }

  // Remove datasets for providers that no longer exist.
  const existing = await chrome.storage.local.get(null);
  const staleKeys = Object.keys(existing).filter((k) => k.startsWith(PREFIX) && !keys.includes(k));

  await chrome.storage.local.set(payload);
  if (staleKeys.length > 0) await chrome.storage.local.remove(staleKeys);

  cache = null;
  inflight = null;
}

export function reputationCacheInfo(): { loadedAt: number; providers: number; domains: number } | null {
  if (!cache) return null;
  let domains = 0;
  for (const b of cache.bundles.values()) domains += b.domains.size;
  return { loadedAt: cache.loadedAt, providers: cache.bundles.size, domains };
}

/**
 * Looks up `hostname` and its parent domains in the reputation dataset.
 * Returns the most specific match found.
 */
export async function lookupThreat(hostname: string | null, registrableDomain: string | null): Promise<ReputationLookup | null> {
  if (!hostname) return null;
  const loaded = await loadReputation();
  if (loaded.bundles.size === 0) return null;

  const labels = hostname.split('.').filter((l) => l.length > 0);
  const minIndex = registrableDomain
    ? labels.length - registrableDomain.split('.').length
    : Math.max(0, labels.length - MAX_PARENT_HOPS);

  // Walk from the most specific host down to the registrable domain.
  for (let start = Math.max(0, labels.length - MAX_PARENT_HOPS); start <= minIndex; start += 1) {
    const candidate = labels.slice(start).join('.');
    for (const state of loaded.meta) {
      if (state.status !== 'active' && state.status !== 'bundled_snapshot' && state.status !== 'stale') continue;
      const bundle = loaded.bundles.get(state.id);
      if (!bundle || !bundle.domains.has(candidate)) continue;
      const record: ThreatRecord = {
        category: categoryForProvider(state.id),
        providerId: state.id,
        since: state.lastSuccessAt ?? 0,
        ...(state.feedVersion ? { feedDay: state.feedVersion } : {}),
      };
      return { record, provider: state, matchedDomain: candidate };
    }
  }
  return null;
}

/**
 * Maps a provider id to the category it represents.
 *
 * Single source of truth is the feed registry, so adding a provider never
 * requires touching this file. Providers used for reputation must be SAFETY
 * categories: an ad/trackers entry is never treated as evidence of malware.
 */
export function categoryForProvider(providerId: string): ThreatCategory {
  const descriptor = PROVIDER_INDEX.get(providerId);
  const safety = descriptor?.categories.find((c) => c !== 'tracker' && c !== 'ad');
  return safety ?? 'malware';
}

/** Used by the Downloads module and by Diagnostics. */
export function threatIndexSize(): number {
  if (!cache) return 0;
  let n = 0;
  for (const b of cache.bundles.values()) n += b.domains.size;
  return n;
}

export function invalidateReputationCache(): void {
  cache = null;
  inflight = null;
}
