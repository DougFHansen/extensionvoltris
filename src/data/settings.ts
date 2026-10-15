/**
 * Settings store: schema, defaults, migration and validation.
 *
 * Settings arriving from storage are ALWAYS validated. A corrupted or
 * hand-edited value must never widen permissions or crash the service worker.
 */
import { DEFAULT_SETTINGS, type Settings } from '../core/types';
import { get, set, K } from '../platform/storage';

const BOOLEAN_KEYS = [
  'protectionEnabled',
  'blockMalware',
  'blockPhishing',
  'blockScam',
  'blockMalwareDistribution',
  'phishingEngineEnabled',
  'showHoverWarnings',
  'scamPageAnalysis',
  'blockTrackers',
  'blockAds',
  'blockThirdPartyOnly',
  'downloadProtection',
  'warnDangerousExtensions',
  'warnDoubleExtensions',
  'storeHistory',
  'storeFullUrls',
  'showNotifications',
  'autoUpdate',
  'reducedMotion',
] as const satisfies readonly (keyof Settings)[];

const ENUM_KEYS = {
  downloadAction: ['alert', 'cancel'],
  theme: ['system', 'light', 'dark'],
  uiLanguage: ['auto', 'en', 'pt_BR'],
} as const satisfies Record<string, readonly string[]>;

let cached: Settings | null = null;

function coerce(raw: unknown): Settings {
  const source = (raw !== null && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const out: Record<string, unknown> = { ...DEFAULT_SETTINGS };

  for (const key of BOOLEAN_KEYS) {
    const value = source[key];
    out[key] = typeof value === 'boolean' ? value : (DEFAULT_SETTINGS[key] as unknown as boolean);
  }

  for (const [key, allowed] of Object.entries(ENUM_KEYS)) {
    const value = source[key];
    out[key] = typeof value === 'string' && (allowed as readonly string[]).includes(value)
      ? value
      : (DEFAULT_SETTINGS[key as keyof Settings] as unknown as string);
  }

  const interval = source.updateIntervalHours;
  const numeric = typeof interval === 'number' && Number.isFinite(interval) ? Math.round(interval) : NaN;
  out.updateIntervalHours = Number.isNaN(numeric)
    ? DEFAULT_SETTINGS.updateIntervalHours
    : Math.min(168, Math.max(1, numeric));

  out.version = DEFAULT_SETTINGS.version;
  return out as unknown as Settings;
}

export async function getSettings(): Promise<Settings> {
  if (cached) return cached;
  const raw = await get<unknown>(K.settings);
  cached = coerce(raw);
  if (raw === null) await set(K.settings, cached);
  return cached;
}

/** Synchronous best-effort read for hot paths (UI contexts preload first). */
export function getSettingsCached(): Settings | null {
  return cached;
}

export function primeSettings(value: Settings): void {
  cached = value;
}

export type SettingsPatch = Partial<Omit<Settings, 'version'>>;

/**
 * Applies a validated patch. Unknown keys are dropped, values are coerced and
 * the result is written atomically.
 */
export async function updateSettings(patch: SettingsPatch): Promise<Settings> {
  const current = await getSettings();
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(patch)) {
    if (!(key in DEFAULT_SETTINGS)) continue; // drop unknown keys
    if (key === 'version') continue;
    sanitized[key] = value;
  }
  const next = coerce({ ...(current as unknown as Record<string, unknown>), ...sanitized });
  await set(K.settings, next);
  cached = next;
  return next;
}

export async function resetSettings(): Promise<Settings> {
  await set(K.settings, DEFAULT_SETTINGS);
  cached = DEFAULT_SETTINGS;
  return DEFAULT_SETTINGS;
}

/** Exposed for Diagnostics: the exact defaults we ship. */
export function defaultSettings(): Settings {
  return DEFAULT_SETTINGS;
}

export function invalidateSettingsCache(): void {
  cached = null;
}
