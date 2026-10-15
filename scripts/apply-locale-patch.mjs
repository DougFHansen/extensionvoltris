#!/usr/bin/env node
/**
 * One-off migration for the metric-honesty revision.
 *
 * Applies locale-specific edits (additions, rewrites and removals) to both
 * catalogs, keeping them sorted and structurally identical.
 *
 * Usage: node scripts/apply-locale-patch.mjs <patch.json>
 *
 * Patch shape:
 *   { "en": { "set": {...}, "remove": [...] },
 *     "pt_BR": { "set": {...}, "remove": [...] } }
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const patch = JSON.parse(readFileSync(process.argv[2], 'utf8'));

for (const locale of ['en', 'pt_BR']) {
  const file = resolve(ROOT, `src/_locales/${locale}/messages.json`);
  const catalog = JSON.parse(readFileSync(file, 'utf8'));
  const before = Object.keys(catalog).length;

  for (const key of patch[locale]?.remove ?? []) delete catalog[key];
  for (const [key, value] of Object.entries(patch[locale]?.set ?? {})) catalog[key] = value;

  const sorted = {};
  for (const key of Object.keys(catalog).sort()) sorted[key] = catalog[key];
  writeFileSync(file, `${JSON.stringify(sorted, null, 2)}\n`, 'utf8');
  process.stdout.write(`[locale] ${locale}: ${before} -> ${Object.keys(sorted).length} keys\n`);
}
