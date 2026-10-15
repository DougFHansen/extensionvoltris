/**
 * chrome.alarms wiring for periodic feed updates.
 *
 * The service worker is event driven and may be suspended at any time, so we
 * never assume continuity: `runStartupTasks` re-establishes state whenever the
 * worker wakes, and the alarm is only a nudge.
 */
import { FEED_MIN_UPDATE_INTERVAL_MIN } from '../core/constants';
import { K } from '../platform/storage';
import { getSettings } from '../data/settings';
import { recordHistory } from '../data/history';
import { clampInterval, configuredProviderIds, loadCredentials, loadDataset } from '../feeds/updater';
import { refreshAndRebuild } from './rules';

const ALARM_UPDATE = 'vbs.feed-update';

export async function scheduleAlarms(): Promise<void> {
  // `chrome.alarms` is undefined when the permission is missing. Degrade to
  // "no periodic updates" instead of throwing.
  if (typeof chrome.alarms === 'undefined') return;
  const settings = await getSettings();
  await chrome.alarms.clear(ALARM_UPDATE);
  if (!settings.autoUpdate) return;
  const minutes = Math.max(30, clampInterval(settings.updateIntervalHours) * 60);
  chrome.alarms.create(ALARM_UPDATE, {
    // The first run happens quickly after install; Chrome clamps very small
    // periods, and we stay far above the documented minimum anyway.
    delayInMinutes: FEED_MIN_UPDATE_INTERVAL_MIN,
    periodInMinutes: minutes,
  });
}

export async function handleAlarm(alarm: chrome.alarms.Alarm): Promise<void> {
  if (alarm.name !== ALARM_UPDATE) return;
  await runUpdateCycle('alarm');
}

let cycleInFlight: Promise<void> | null = null;

export async function runStartupTasks(): Promise<void> {
  await scheduleAlarms();
  const settings = await getSettings();
  if (!settings.autoUpdate) return;

  // Only refresh when the stored dataset is older than half the interval, so we
  // never hit the network on every browser start.
  const dataset = await loadDataset();
  const ageHours = dataset.updatedAt === 0 ? Number.POSITIVE_INFINITY : (Date.now() - dataset.updatedAt) / 3_600_000;
  if (ageHours < clampInterval(settings.updateIntervalHours) / 2) return;

  void runUpdateCycle('startup');
}

/**
 * Single-flight update cycle. Concurrent triggers share one run.
 */
export function runUpdateCycle(trigger: 'alarm' | 'startup' | 'manual'): Promise<void> {
  if (cycleInFlight) return cycleInFlight;
  cycleInFlight = (async () => {
    try {
      const credentials = await loadCredentials();
      const configured = await configuredProviderIds();
      for (const id of configured) {
        const value = credentials.get(id);
        if (value) credentials.set(id, value);
      }

      const overview = await refreshAndRebuild(trigger === 'manual');
      const settings = await getSettings();
      const active = overview.states.filter((s) => s.status === 'active' || s.status === 'stale').length;
      const failed = overview.states.filter((s) => s.status === 'error' || s.status === 'not_configured');

      await setCycleError(null);

      if (failed.length > 0) {
        await recordHistory({
          kind: 'list_error',
          domain: '',
          providerId: `failed:${failed.map((s) => s.id).join(',')}`,
          storeFullUrls: settings.storeFullUrls,
        });
      } else {
        await recordHistory({
          kind: 'list_updated',
          domain: '',
          providerId: `providers:${active}`,
          storeFullUrls: settings.storeFullUrls,
        });
      }
    } catch (error) {
      // A failure here means the extension is running with NO threat data, so it
      // is blocking nothing. Swallowing it - as this used to - leaves the user
      // believing they are protected while no rule is installed. The reason is
      // recorded so Diagnostics and the interface can say so out loud.
      await setCycleError({
        trigger,
        message: error instanceof Error ? error.message : String(error),
        name: error instanceof Error ? error.name : 'unknown',
        at: Date.now(),
      });
      try {
        const settings = await getSettings();
        await recordHistory({
          kind: 'list_error',
          domain: '',
          providerId: `cycle:${trigger}`,
          storeFullUrls: settings.storeFullUrls,
        });
      } catch {
        /* nothing further can be done */
      }
    } finally {
      cycleInFlight = null;
    }
  })();
  return cycleInFlight;
}

export interface CycleError {
  readonly trigger: 'alarm' | 'startup' | 'manual';
  readonly message: string;
  readonly name: string;
  readonly at: number;
}

/** Records, or clears, the reason the last update cycle failed. */
async function setCycleError(error: CycleError | null): Promise<void> {
  try {
    await chrome.storage.local.set({ [K.feedCycleError]: error });
  } catch {
    /* storage unavailable; the UI degrades to "unknown" */
  }
}

export async function getCycleError(): Promise<CycleError | null> {
  try {
    const raw = await chrome.storage.local.get(K.feedCycleError);
    const value = raw[K.feedCycleError];
    return value && typeof value === 'object' && typeof (value as CycleError).message === 'string'
      ? (value as CycleError)
      : null;
  } catch {
    return null;
  }
}
