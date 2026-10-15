/**
 * Service worker bootstrap: one-time, idempotent initialisation.
 *
 * Everything here is safe to run again after the worker is suspended and
 * revived, which is an explicit acceptance criterion.
 */
import { getSettings } from '../data/settings';
import { preloadPsl } from '../security/psl';
import { scheduleAlarms, runStartupTasks } from './alarms';
import { ensureRules, getProtectionState } from './rules';
import { invalidateAllCaches } from '../data/caches';

let ready: Promise<void> | null = null;

export function bootstrap(): Promise<void> {
  if (ready) return ready;
  ready = (async () => {
    invalidateAllCaches();
    preloadPsl();
    await getSettings();
    await scheduleAlarms();
    // Rules are restored lazily on the first event that needs them, so worker
    // startup stays under a millisecond in the common case.
    void getProtectionState();
    void ensureRules();
    await runStartupTasks();
  })().catch(() => {
    // A failed bootstrap must never block the event pipeline.
    ready = null;
  });
  return ready;
}

/** Test hook: forces the next `bootstrap()` to run again. */
export function resetBootstrapForTests(): void {
  ready = null;
}
