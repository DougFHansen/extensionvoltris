#!/usr/bin/env node
/**
 * Normalizes the locale catalogs.
 *
 * Chrome's i18n schema requires every entry to be an object with a `message`
 * field (and an optional `description`). A bare string entry makes the whole
 * locale file fail to load, which would silently drop an entire language.
 *
 * This script rewrites both catalogs in a canonical, sorted form so the two
 * files can be diffed line by line.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LOCALES = ['en', 'pt_BR'];

function normalize(catalog) {
  const out = {};
  for (const key of Object.keys(catalog).sort()) {
    const entry = catalog[key];
    if (typeof entry === 'string') {
      out[key] = { message: entry };
    } else if (entry && typeof entry.message === 'string') {
      out[key] = entry.description ? { message: entry.message, description: entry.description } : { message: entry.message };
    } else {
      throw new Error(`Invalid entry for "${key}"`);
    }
  }
  return out;
}

let changed = 0;
for (const locale of LOCALES) {
  const file = resolve(ROOT, `src/_locales/${locale}/messages.json`);
  const before = readFileSync(file, 'utf8');
  const catalog = JSON.parse(before);
  const normalized = normalize(catalog);
  const after = `${JSON.stringify(normalized, null, 2)}\n`;
  if (after !== before) {
    writeFileSync(file, after, 'utf8');
    changed += 1;
  }
  process.stdout.write(`[i18n] ${locale}: ${Object.keys(normalized).length} keys\n`);
}

process.stdout.write(`[i18n] ${changed} file(s) rewritten\n`);
