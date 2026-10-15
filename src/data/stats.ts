/**
 * Local statistics.
 *
 * METRIC HONESTY: every counter here is driven by a real, observable event from
 * an API that is available in a PUBLISHED extension. See the contract in
 * `src/core/types.ts`.
 *
 * Specifically, `declarativeNetRequest.onRuleMatchedDebug` is NOT used: Chrome
 * documents it as unpacked-only and "intended to be used for debugging purposes
 * only". Counting it would produce statistics that silently read zero after a
 * store install.
 *
 * Storage discipline:
 *  - `topBlockedDomains` is capped so it cannot grow without bound.
 *  - `blockedByDay` is pruned to the last 90 days.
 *  - Writes are debounced and serialised so concurrent events cannot be lost.
 */
import { emptyStats, type DownloadRiskVerdict, type Stats, type ThreatCategory } from '../core/types';
import { get, set, K } from '../platform/storage';

const TOP_DOMAINS_LIMIT = 50;
const DAY_WINDOW = 90;

let cached: Stats | null = null;
let pending: Stats | null = null;
let flushTimer: ReturnType<typeof setTimeout> | null = null;
const FLUSH_DEBOUNCE_MS = 400;

/**
 * Serializes counter updates.
 *
 * `recordBlockedNavigation` is called from `webNavigation.onErrorOccurred`, which
 * can fire several times in quick succession. Without this queue two concurrent
 * updates would both read the same base snapshot and the second would silently
 * discard the first one's increment - losing real observed events.
 */
let queue: Promise<void> = Promise.resolve();

/** Mutable view of `Stats`. The public type is readonly so callers cannot mutate. */
type MutableStats = { -readonly [K in keyof Stats]: Stats[K] };
type MutableCountMap = Record<string, number>;

function today(now: number): string {
  const d = new Date(now);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
}

function pruneDays(byDay: Record<string, number>, now: number): Record<string, number> {
  const cutoff = new Date(now - DAY_WINDOW * 86_400_000).toISOString().slice(0, 10);
  const out: Record<string, number> = {};
  let kept = 0;
  for (const key of Object.keys(byDay).sort()) {
    if (key >= cutoff && kept < DAY_WINDOW) {
      out[key] = byDay[key]!;
      kept += 1;
    }
  }
  return out;
}

function pruneTop(top: Record<string, number>): Record<string, number> {
  const entries = Object.entries(top)
    .filter(([, n]) => Number.isFinite(n) && n > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_DOMAINS_LIMIT);
  return Object.fromEntries(entries);
}

export async function getStats(): Promise<Stats> {
  if (cached) return cached;
  const raw = await get<unknown>(K.stats);
  cached = coerceStats(raw);
  return cached;
}

/** Repairs a stored value written by an older build or corrupted by hand. */
function coerceStats(raw: unknown): Stats {
  const base = emptyStats();
  if (!raw || typeof raw !== 'object') return base;
  const source = raw as Record<string, unknown>;

  const num = (key: string): number =>
    typeof source[key] === 'number' && Number.isFinite(source[key]) ? (source[key] as number) : 0;
  const map = (key: string): Record<string, number> =>
    source[key] && typeof source[key] === 'object' ? (source[key] as Record<string, number>) : {};

  return {
    blockedNavigations: num('blockedNavigations'),
    blockedNavigationsByCategory: map('blockedNavigationsByCategory'),
    suspiciousDetected: num('suspiciousDetected'),
    downloadsFlagged: num('downloadsFlagged'),
    downloadsCancelled: num('downloadsCancelled'),
    allowlisted: num('allowlisted'),
    blockedByDay: map('blockedByDay'),
    topBlockedDomains: map('topBlockedDomains'),
    updatedAt: num('updatedAt'),
  };
}

export function primeStats(value: Stats): void {
  cached = value;
}

export async function resetStats(): Promise<void> {
  cached = emptyStats();
  pending = null;
  await set(K.stats, cached);
}

export interface BlockedNavigationObservation {
  readonly category: ThreatCategory;
  /** Registrable domain of the blocked navigation, when available. */
  readonly domain: string | null;
  readonly at: number;
}

/**
 * Records a top-level navigation we OBSERVED being blocked.
 *
 * The caller must only invoke this after a `webNavigation.onErrorOccurred`
 * event with `net::ERR_BLOCKED_BY_CLIENT` whose destination matches one of our
 * own threat rules. That is a real, production-available observation.
 */
export function recordBlockedNavigation(observation: BlockedNavigationObservation): void {
  void apply((stats) => {
    const next: MutableStats = {
      ...stats,
      blockedByDay: { ...stats.blockedByDay } as MutableCountMap,
      topBlockedDomains: { ...stats.topBlockedDomains } as MutableCountMap,
      blockedNavigationsByCategory: { ...stats.blockedNavigationsByCategory },
    };

    next.blockedNavigations += 1;
    const byCategory = next.blockedNavigationsByCategory as MutableCountMap;
    byCategory[observation.category] = (byCategory[observation.category] ?? 0) + 1;

    const day = today(observation.at);
    const byDay = next.blockedByDay as MutableCountMap;
    byDay[day] = (byDay[day] ?? 0) + 1;
    if (observation.domain) {
      const top = next.topBlockedDomains as MutableCountMap;
      top[observation.domain] = (top[observation.domain] ?? 0) + 1;
    }

    return {
      ...next,
      blockedByDay: pruneDays(next.blockedByDay, observation.at),
      topBlockedDomains: pruneTop(next.topBlockedDomains),
      updatedAt: observation.at,
    };
  });
}

export function recordSuspiciousDetection(): void {
  void apply((stats) => ({ ...stats, suspiciousDetected: stats.suspiciousDetected + 1, updatedAt: Date.now() }));
}

export function recordAllowlisted(): void {
  void apply((stats) => ({ ...stats, allowlisted: stats.allowlisted + 1, updatedAt: Date.now() }));
}

export function recordDownload(verdict: DownloadRiskVerdict, cancelled: boolean): void {
  void apply((stats) => ({
    ...stats,
    downloadsFlagged: stats.downloadsFlagged + 1,
    downloadsCancelled: stats.downloadsCancelled + (cancelled ? 1 : 0),
    updatedAt: Date.now(),
  }));
}

async function apply(mutate: (stats: Stats) => MutableStats): Promise<void> {
  queue = queue.then(async () => {
    const stats = await getStats();
    const next = mutate(stats);
    cached = next;
    pending = { ...next };
    scheduleFlush();
  });
  return queue;
}

function scheduleFlush(): void {
  if (flushTimer !== null) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    const snapshot = pending;
    pending = null;
    if (snapshot) void set(K.stats, snapshot);
  }, FLUSH_DEBOUNCE_MS);
}

/** Forces an immediate write. Used on suspend and before the panel closes. */
export async function flushStats(): Promise<void> {
  // Wait for any queued update to land first, otherwise we could flush an
  // out-of-date snapshot.
  await queue;
  if (flushTimer !== null) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  if (pending) {
    await set(K.stats, pending);
    pending = null;
  }
}

export function invalidateStatsCache(): void {
  cached = null;
  pending = null;
  queue = Promise.resolve();
}

/** Dense series for the dashboard chart. */
export function dailySeries(stats: Stats, days: number): { day: string; count: number }[] {
  const out: { day: string; count: number }[] = [];
  const now = Date.now();
  for (let i = days - 1; i >= 0; i -= 1) {
    const day = today(now - i * 86_400_000);
    out.push({ day, count: stats.blockedByDay[day] ?? 0 });
  }
  return out;
}
