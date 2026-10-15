/**
 * Interface language.
 *
 * DEFAULT BEHAVIOUR IS THE BROWSER'S
 * ----------------------------------
 * `chrome.i18n` already selects `_locales/<lang>` from the browser UI language, so
 * a pt-BR browser gets Portuguese and an en-US browser gets English with no code
 * at all. That remains the default (`'auto'`) and the common case.
 *
 * WHY AN OVERRIDE EXISTS
 * ---------------------
 * A user whose browser is in one language may still want the extension in
 * another - a Portuguese speaker on an English-locked work machine, or someone
 * sharing a screenshot. `chrome.i18n` cannot be overridden, so an explicit
 * choice loads the corresponding catalog directly.
 *
 * WHY THE CATALOG IS FETCHED RATHER THAN BUNDLED
 * ----------------------------------------------
 * Importing both `messages.json` files would add ~70 KB to every page bundle for
 * a feature most users never touch. Fetching `_locales/<lang>/messages.json`
 * from the extension's own origin costs one request, only when an override is
 * actually in use, and keeps the shipped pages small.
 *
 * `t()` stays synchronous: every page loads the override during its existing
 * async initialisation, before it renders anything.
 */
import type { UiLanguage } from '../../core/types';

interface CatalogEntry {
  readonly message: string;
}

/** Loaded override catalog. `null` means "defer entirely to `chrome.i18n`". */
let override: ReadonlyMap<string, string> | null = null;
let loadedLanguage: UiLanguage = 'auto';
let loading: Promise<void> | null = null;

/**
 * Prepares the override catalog. Safe to call on every page load.
 *
 * Always resolves, even if the catalog cannot be read: a language that fails to
 * load must degrade to the browser's language, never to raw message keys.
 */
export async function loadUiLanguage(language: UiLanguage): Promise<void> {
  if (language === loadedLanguage) return;
  if (loading) return loading;

  loading = (async () => {
    if (language === 'auto') {
      override = null;
      loadedLanguage = 'auto';
      return;
    }
    try {
      const response = await fetch(chrome.runtime.getURL(`_locales/${language}/messages.json`));
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const json = (await response.json()) as Record<string, CatalogEntry>;
      const map = new Map<string, string>();
      for (const [key, value] of Object.entries(json)) {
        // A catalog entry with no message is a packaging bug; skip it rather than
        // shadowing a working `chrome.i18n` string with an empty one.
        if (value && typeof value.message === 'string' && value.message.length > 0) map.set(key, value.message);
      }
      override = map.size > 0 ? map : null;
      loadedLanguage = language;
    } catch {
      // Fall back to the browser's language rather than showing message keys.
      override = null;
      loadedLanguage = 'auto';
    }
  })();

  try {
    await loading;
  } finally {
    loading = null;
  }
}

/** Which language is in effect right now, after the override is applied. */
export function activeLanguage(): string {
  if (override !== null) return loadedLanguage;
  try {
    return chrome.i18n.getUILanguage();
  } catch {
    return 'en';
  }
}

/**
 * Applies `$1`-style placeholders the same way `chrome.i18n` does.
 *
 * Without this, a message read from an override catalog would show the literal
 * placeholder to the user.
 */
function substitute(message: string, substitutions?: string | string[]): string {
  if (substitutions === undefined) return message;
  const values = Array.isArray(substitutions) ? substitutions : [substitutions];
  return message.replace(/\$(\d)/g, (match, digit: string) => {
    const value = values[Number(digit) - 1];
    // Chrome substitutes nothing and leaves the placeholder when the index is
    // out of range; matching that keeps both paths visually identical.
    return value === undefined ? match : value;
  });
}

/** Resolves a message key, preferring an explicit language override. */
export function translate(key: string, substitutions?: string | string[]): string {
  const overridden = override?.get(key);
  if (overridden !== undefined) return substitute(overridden, substitutions);

  try {
    const message = chrome.i18n.getMessage(key, substitutions as never);
    return message.length > 0 ? message : key;
  } catch {
    return key;
  }
}

/** The `t()` name every UI module already imports from `./components`. */
export const t = translate;

/** Test hook: drops any loaded override so a suite starts from a known state. */
export function resetUiLanguage(): void {
  override = null;
  loadedLanguage = 'auto';
  loading = null;
}
