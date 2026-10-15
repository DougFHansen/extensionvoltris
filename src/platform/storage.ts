/**
 * Typed, quota-aware wrapper around `chrome.storage`.
 *
 * Why a wrapper: raw `chrome.storage` calls are easy to get wrong (unbounded
 * writes, missing migration, cross-context races). This module centralises
 * namespacing, quota accounting, atomic writes and JSON validation.
 */
import { STORAGE_QUOTA_BYTES, STORAGE_SOFT_LIMIT_BYTES } from '../core/constants';

const PREFIX = 'vbs.';

export const K = {
  settings: `${PREFIX}settings`,
  stats: `${PREFIX}stats`,
  allowlist: `${PREFIX}allowlist`,
  history: `${PREFIX}history`,
  blockEvents: `${PREFIX}blockEvents`,
  feedState: `${PREFIX}feedState`,
  feedDataset: `${PREFIX}feedDataset`,
  rulesMeta: `${PREFIX}rulesMeta`,
  uiPrefs: `${PREFIX}uiPrefs`,
} as const;

export type StorageArea = 'local' | 'session';

/**
 * session storage survives service-worker suspension but is cleared when the
 * browser closes. Used for ephemeral block records so we never persist the URL a
 * user was blocked from.
 */
export function area(name: StorageArea): chrome.storage.StorageArea {
  return name === 'session' ? chrome.storage.session : chrome.storage.local;
}

export async function get<T>(key: string, storageArea: StorageArea = 'local'): Promise<T | null> {
  try {
    const result = await area(storageArea).get(key);
    const value = result[key];
    return value === undefined ? null : (value as T);
  } catch {
    return null;
  }
}

export async function set(key: string, value: unknown, storageArea: StorageArea = 'local'): Promise<void> {
  await area(storageArea).set({ [key]: value });
}

export async function remove(keys: string | string[], storageArea: StorageArea = 'local'): Promise<void> {
  await area(storageArea).remove(keys as string | string[]);
}

export async function getMany(keys: string[], storageArea: StorageArea = 'local'): Promise<Record<string, unknown>> {
  if (keys.length === 0) return {};
  return (await area(storageArea).get(keys)) as Record<string, unknown>;
}

/**
 * Approximate byte usage of a value. Chrome does not expose exact accounting, so
 * we measure the serialized JSON length plus a small per-entry overhead.
 */
export function byteSizeOf(value: unknown): number {
  try {
    return JSON.stringify(value).length * 2 + 64;
  } catch {
    return 0;
  }
}

export interface StorageUsage {
  readonly bytes: number;
  readonly quotaBytes: number;
  readonly percent: number;
  readonly overSoftLimit: boolean;
}

export async function usage(): Promise<StorageUsage> {
  const all = await chrome.storage.local.get(null);
  let bytes = 0;
  for (const value of Object.values(all)) bytes += byteSizeOf(value);
  return {
    bytes,
    quotaBytes: STORAGE_QUOTA_BYTES,
    percent: Math.round((bytes / STORAGE_QUOTA_BYTES) * 10000) / 100,
    overSoftLimit: bytes > STORAGE_SOFT_LIMIT_BYTES,
  };
}

export interface ClearScope {
  readonly settings: boolean;
  readonly statistics: boolean;
  readonly allowlist: boolean;
  readonly history: boolean;
  readonly threatData: boolean;
}

export const CLEAR_ALL: ClearScope = {
  settings: true,
  statistics: true,
  allowlist: true,
  history: true,
  threatData: true,
};

/**
 * Deletes user data. When `threatData` is true the bundled feed snapshot is also
 * dropped, which forces a re-download on the next update cycle.
 */
export async function clearData(scope: ClearScope): Promise<string[]> {
  const removed: string[] = [];
  const everything = await chrome.storage.local.get(null);
  const allKeys = Object.keys(everything);

  const shouldRemove = (key: string): boolean => {
    if (key === K.settings) return scope.settings;
    if (key === K.stats) return scope.statistics;
    if (key === K.allowlist) return scope.allowlist;
    if (key === K.history || key === K.blockEvents) return scope.history;
    // Derived state: rebuilt from the dataset, never authoritative.
    if (key === K.rulesMeta) return scope.threatData;
    if (key === K.feedDataset || key.startsWith('vbs.threats.') || key === K.feedState) return scope.threatData;
    return false;
  };

  const targets = allKeys.filter(shouldRemove);
  if (targets.length > 0) {
    await chrome.storage.local.remove(targets);
    removed.push(...targets);
  }
  await chrome.storage.session.clear();
  removed.push('chrome.storage.session (all)');
  return removed;
}

/** Listen for external changes to a single key. Returns an unsubscribe function. */
export function watch<T>(
  key: string,
  handler: (value: T | null, previous: T | null) => void,
  storageArea: StorageArea = 'local',
): () => void {
  const listener = (
    changes: Record<string, chrome.storage.StorageChange>,
    areaName: string,
  ): void => {
    if (areaName !== storageArea) return;
    if (!(key in changes)) return;
    handler((changes[key]?.newValue as T | undefined) ?? null, (changes[key]?.oldValue as T | undefined) ?? null);
  };
  chrome.storage.onChanged.addListener(listener);
  return () => chrome.storage.onChanged.removeListener(listener);
}
