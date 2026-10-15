/**
 * Service worker event listeners.
 *
 * Every listener:
 *  - validates its input,
 *  - never blocks the browser's event pipeline on network work,
 *  - is registered at module scope so a suspended worker resumes correctly.
 *
 * DEFENSIVE REGISTRATION: each API is probed before it is used. A missing or
 * renamed API must disable exactly one capability, never silently take down the
 * listeners registered after it. (This is not theoretical: an undeclared
 * `chrome.alarms` permission once made every subsequent registration throw.)
 */
import { handleAlarm, runStartupTasks, scheduleAlarms } from './alarms';
import { ensureRules, getProtectionState, getRulesMeta, previewRulePlan } from './rules';
import { handleMessage } from './messages';
import { onTabUpdates } from './navigation';
import { configureObservationPreference, installBlockObservation } from './observation';
import { registerDownloadListeners } from './downloads';
import { flushPendingWrites } from '../data/caches';
import { markRegistered, markUnavailable } from './listener-registry';

function safeRegister(name: string, register: () => void): void {
  try {
    register();
    markRegistered(name);
  } catch {
    markUnavailable(name);
  }
}

export function installListeners(): void {
  safeRegister('runtime.onInstalled', () => {
    chrome.runtime.onInstalled.addListener((details) => {
      void handleInstalled(details);
    });
  });

  safeRegister('runtime.onStartup', () => {
    chrome.runtime.onStartup.addListener(() => {
      void runStartupTasks();
    });
  });

  safeRegister('alarms.onAlarm', () => {
    chrome.alarms.onAlarm.addListener((alarm) => {
      void handleAlarm(alarm);
    });
  });

  safeRegister('runtime.onSuspend', () => {
    // MV2 only; absent in MV3, which is not an error.
    chrome.runtime.onSuspend?.addListener(() => {
      void flushPendingWrites();
    });
  });

  // Persist debounced writes before the worker goes away. MV3 has no reliable
  // suspend event, so this alarm is the reliable backstop.
  safeRegister('runtime.onMessage', () => {
    void handleMessage();
  });

  // PRODUCTION block observation. `webNavigation` is available to published
  // extensions, unlike the unpacked-only `onRuleMatchedDebug` this replaced.
  safeRegister('webNavigation.onErrorOccurred', () => {
    installBlockObservation();
  });

  safeRegister('tabs.onUpdated', () => {
    onTabUpdates();
  });

  safeRegister('downloads.onDeterminingFilename', () => {
    registerDownloadListeners();
  });
}

export { configureObservationPreference };

async function handleInstalled(details: chrome.runtime.InstalledDetails): Promise<void> {
  if (details.reason === 'install') {
    await ensureRules(true);
    await refreshFeedsOnInstall();
  } else if (details.reason === 'update') {
    await scheduleAlarms();
    await ensureRules(true);
  }
}

async function refreshFeedsOnInstall(): Promise<void> {
  const { runUpdateCycle } = await import('./alarms');
  await runUpdateCycle('manual');
}

export { getProtectionState, getRulesMeta, previewRulePlan };
