#!/usr/bin/env node
/**
 * Adds or updates messages in every locale catalog, keeping the files sorted
 * and structurally identical so `tests/unit/i18n.test.ts` stays green.
 *
 * Usage: node scripts/add-message.mjs <file.json>
 *        node scripts/add-message.mjs '{"key":{"message":"..."}}'
 *
 * A file path is accepted because shell quoting of JSON is unreliable across
 * platforms.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const arg = process.argv[2];
if (!arg) {
  process.stderr.write('usage: node scripts/add-message.mjs <file.json | inline-json>\n');
  process.exit(1);
}

const raw = existsSync(arg) ? readFileSync(arg, 'utf8') : arg;
const additions = JSON.parse(raw);
if (typeof additions !== 'object' || additions === null || Array.isArray(additions)) {
  process.stderr.write('expected a JSON object of key -> { message, description? }\n');
  process.exit(1);
}

for (const locale of ['en', 'pt_BR']) {
  const file = resolve(ROOT, `src/_locales/${locale}/messages.json`);
  const catalog = JSON.parse(readFileSync(file, 'utf8'));
  for (const [key, value] of Object.entries(additions)) {
    catalog[key] = value;
  }
  const sorted = {};
  for (const key of Object.keys(catalog).sort()) sorted[key] = catalog[key];
  writeFileSync(file, `${JSON.stringify(sorted, null, 2)}\n`, 'utf8');
  process.stdout.write(`[i18n] ${locale}: ${Object.keys(sorted).length} keys\n`);
}
