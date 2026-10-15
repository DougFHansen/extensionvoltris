/**
 * Store listing limits.
 *
 * Chrome Web Store rejects an upload outright when these strings exceed their
 * caps, and the message it shows does not name the offending field. Two of them
 * did exceed the limit in the 1.0.0/1.1.0 cycle and were caught only while
 * preparing the submission, which is exactly the wrong moment to find out.
 *
 * Limits verified against Chrome's documentation:
 *   name         45 characters
 *   short_name   12 characters
 *   description 132 characters
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

/** Counted in code points, matching Chrome. */
const count = (value: string): number => [...value].length;

const LIMITS = {
  extension_name: 45,
  extension_short_name: 12,
  extension_description: 132,
} as const;

const LOCALES = ['en', 'pt_BR'] as const;

type Catalog = Record<string, { message: string }>;

const catalogs = new Map<string, Catalog>(
  LOCALES.map((locale) => [locale, JSON.parse(readFileSync(`src/_locales/${locale}/messages.json`, 'utf8')) as Catalog]),
);

function catalogFor(locale: string): Catalog {
  const found = catalogs.get(locale);
  if (!found) throw new Error(`locale ${locale} not loaded`);
  return found;
}

describe.each(LOCALES)('locale %s', (locale) => {
  const catalog = catalogFor(locale);

  it.each(Object.entries(LIMITS))('%s fits the store limit', (key, max) => {
    const message = catalog[key]?.message;
    expect(message, `${key} missing from ${locale}`).toBeTruthy();
    expect(count(message!), `${key} is ${count(message!)} characters, the limit is ${max}`).toBeLessThanOrEqual(max);
  });

  it('short_name contains no spaces, which Chrome prefers', () => {
    expect(catalog.extension_short_name!.message).not.toMatch(/\s/);
  });

  it('description does not make an absolute security claim', () => {
    // Both stores reject absolute claims ("100% protected", "completely safe").
    expect(catalog.extension_description!.message.toLowerCase()).not.toMatch(/100%|completely safe|guaranteed|unhackable/);
  });
});

describe('manifest', () => {
  const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as Record<string, unknown>;

  it('localises name, short_name and description via __MSG_*__', () => {
    // Literal strings bypass the locale files and cannot be reviewed per language.
    for (const field of ['name', 'short_name', 'description']) {
      expect(manifest[field], `${field} must be a __MSG_*__ reference`).toMatch(/^__MSG_[a-z0-9_]+__$/);
    }
  });

  it('references only message keys that exist in the default locale', () => {
    const defaultLocale = catalogFor(manifest.default_locale as string);
    const fields = ['name', 'short_name', 'description', 'action.default_title'];
    for (const field of fields) {
      const value = field
        .split('.')
        .reduce<unknown>((acc, part) => (acc as Record<string, unknown> | undefined)?.[part], manifest) as string;
      const key = value.match(/^__MSG_(.+)__$/)?.[1];
      expect(key, `${field} is not a __MSG_*__ reference`).toBeTruthy();
      expect(defaultLocale[key!], `${field} references a missing key: ${key}`).toBeTruthy();
    }
  });

  it('uses a version Chrome accepts', () => {
    // One to four dot-separated integers, each 0-65535, no leading zeroes.
    expect(manifest.version).toMatch(/^(0|[1-9]\d*)(\.(0|[1-9]\d*)){0,3}$/);
  });

  it('keeps minimum_chrome_version consistent with what the code needs', () => {
    // MV3 declarativeNetRequest and webNavigation both predate 120 comfortably;
    // the value is asserted so a careless bump cannot silently drop support.
    expect(manifest.minimum_chrome_version).toBe('120');
  });
});

describe('locale catalogues stay aligned', () => {
  it('every locale defines exactly the same keys', () => {
    const reference = Object.keys(catalogFor('en')).sort();
    for (const locale of LOCALES.slice(1)) {
      expect(Object.keys(catalogFor(locale)).sort(), `a locale is missing keys present in en`).toEqual(reference);
    }
  });

  it('no message is an empty string', () => {
    for (const locale of LOCALES) {
      for (const [key, value] of Object.entries(catalogFor(locale))) {
        expect(value.message.trim(), `${locale}/${key} is empty`).not.toBe('');
      }
    }
  });
});
