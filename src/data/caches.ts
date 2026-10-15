/**
 * In-memory cache invalidation.
 *
 * The service worker is suspended aggressively by the browser. Every module that
 * keeps a cache exposes an `invalidateX` function; collecting them here gives
 * the bootstrap a single, auditable place to reset all of them, which is what
 * makes "suspend + resume" safe.
 */
import { invalidateSettingsCache } from '../data/settings';
import { invalidateStatsCache, flushStats } from '../data/stats';
import { invalidateAllowlistCache } from '../data/allowlist';
import { invalidateHistoryCache } from '../data/history';
import { invalidateReputationCache } from '../security/reputation';

export function invalidateAllCaches(): void {
  invalidateSettingsCache();
  invalidateStatsCache();
  invalidateAllowlistCache();
  invalidateHistoryCache();
  invalidateReputationCache();
}

/** Persists pending debounced writes before the worker is torn down. */
export async function flushPendingWrites(): Promise<void> {
  await flushStats();
}
