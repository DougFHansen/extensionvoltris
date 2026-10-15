/**
 * i18n catalog integrity test.
 *
 * Guarantees that every locale exposes the same key set and valid placeholders,
 * which is what keeps the UI from silently falling back to raw key names in one
 * language but not the other.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

interface Catalog {
  [key: string]: { message: string; description?: string };
}

function loadCatalog(locale: string): Catalog {
  return JSON.parse(readFileSync(resolve(process.cwd(), `src/_locales/${locale}/messages.json`), 'utf8')) as Catalog;
}

const LOCALES = readdirSync(resolve(process.cwd(), 'src/_locales')).filter((d) =>
  readdirSync(resolve(process.cwd(), 'src/_locales', d)).includes('messages.json'),
);

function placeholders(message: string): string[] {
  return [...message.matchAll(/\$(\d)/g)].map((m) => m[1]!).sort();
}

describe('i18n catalogs', () => {
  it('ships the required locales', () => {
    expect(LOCALES.sort()).toEqual(['en', 'pt_BR']);
  });

  it('en is the default locale and contains the manifest keys', () => {
    const en = loadCatalog('en');
    expect(en.extension_name?.message).toBeTruthy();
    expect(en.extension_description?.message).toBeTruthy();
  });

  it.each(LOCALES)('%s has no empty messages', (locale) => {
    const catalog = loadCatalog(locale);
    for (const [key, entry] of Object.entries(catalog)) {
      expect(entry, `${locale}/${key} must be an object`).toBeTypeOf('object');
      expect(entry.message, `${locale}/${key} must be non-empty`).toBeTruthy();
    }
  });

  it.each(LOCALES)('%s uses the same key set as en', (locale) => {
    const en = loadCatalog('en');
    const catalog = loadCatalog(locale);
    expect(Object.keys(catalog).sort()).toEqual(Object.keys(en).sort());
  });

  it.each(LOCALES)('%s uses the same positional placeholders as en', (locale) => {
    const en = loadCatalog('en');
    const catalog = loadCatalog(locale);
    for (const [key, entry] of Object.entries(en)) {
      expect(placeholders(catalog[key]!.message), `${locale}/${key}`).toEqual(placeholders(entry.message));
    }
  });

  it.each(LOCALES)('%s declares no invalid message names', (locale) => {
    const catalog = loadCatalog(locale);
    for (const key of Object.keys(catalog)) {
      expect(key, `"${key}" is not a valid chrome.i18n message name`).toMatch(/^[A-Za-z0-9_@]+$/);
    }
  });
});

/** Every key referenced from the source must exist in the catalog. */
describe('i18n usage', () => {
  const sourceFiles = [
    'src/core/types.ts',
    'src/security/unicode.ts',
    'src/security/shortener.ts',
    'src/security/brands.ts',
    'src/feeds/registry.ts',
    'src/background/messages.ts',
    'src/background/navigation.ts',
    'src/background/downloads.ts',
    'src/ui/shared/components.ts',
  ];

  it('every statically referenced t() key exists in en', () => {
    const en = loadCatalog('en');
    const missing = new Set<string>();

    for (const file of sourceFiles) {
      const source = readFileSync(resolve(process.cwd(), file), 'utf8');
      for (const match of source.matchAll(/\bt\('([a-z0-9_]+)'/g)) {
        if (!en[match[1]!]) missing.add(`${file}: ${match[1]}`);
      }
    }

    expect([...missing]).toEqual([]);
  });
});
