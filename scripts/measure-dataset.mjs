/**
 * Computes the real packed dataset size, against the real limit.
 *
 * The updater refuses to store a dataset larger than DATASET_MAX_BYTES. When
 * that gate trips on a FRESH install there is no previous dataset to preserve,
 * so the extension ends up with no threat data and no rules - silently.
 */
import fs from 'node:fs';
import { parseProviderFeed } from '../src/feeds/updater.ts';
import { encodeDomains } from '../src/security/reputation.ts';
import { FEED_REGISTRY } from '../src/feeds/registry.ts';

const DATASET_MAX_BYTES = 10_485_760;
const EFFECTIVE = Math.floor(DATASET_MAX_BYTES * 0.9);

const tmp = 'C:/Users/VOLTRIS/AppData/Local/Temp/opencode/feeds';
const LOCAL = {
  easylist: `${tmp}/easylist.txt`,
  easyprivacy: `${tmp}/easyprivacy.txt`,
};

console.log(`DATASET_MAX_BYTES  ${DATASET_MAX_BYTES} (effective ${EFFECTIVE})\n`);

let total = 0;
const rows = [];

for (const provider of FEED_REGISTRY) {
  if (provider.excludedFromProduct) continue;

  let text;
  if (LOCAL[provider.id] && fs.existsSync(LOCAL[provider.id])) {
    text = fs.readFileSync(LOCAL[provider.id], 'utf8');
  } else {
    process.stdout.write(`fetching ${provider.id}... `);
    try {
      const r = await fetch(provider.feedUrl, { headers: { 'User-Agent': 'voltris-size-measurement' } });
      text = await r.text();
      console.log(`${(text.length / 1024).toFixed(0)} KiB`);
    } catch (e) {
      console.log(`NETWORK FAILED: ${e.name}`);
      rows.push({ id: provider.id, entries: 0, bytes: 0, note: 'network failure' });
      continue;
    }
  }

  try {
    const parsed = parseProviderFeed(provider, text);
    const packed = encodeDomains(parsed.domains);
    const bytes = packed.length * 2;
    total += bytes;
    rows.push({ id: provider.id, entries: parsed.domains.size, bytes });
  } catch (e) {
    const reason = e?.code ?? e?.message ?? 'unknown';
    console.log(`  PARSE FAILED: ${reason}`);
    rows.push({ id: provider.id, entries: 0, bytes: 0, note: reason });
  }
}

console.log('');
for (const r of rows) {
  console.log(`  ${r.id.padEnd(30)} entries=${String(r.entries).padStart(7)}  packed=${(r.bytes / 1024 / 1024).toFixed(2)} MiB`);
}
console.log(`\n  TOTAL packed  ${(total / 1024 / 1024).toFixed(2)} MiB`);
console.log(`  LIMIT         ${(EFFECTIVE / 1024 / 1024).toFixed(2)} MiB`);
console.log(`  EXCEEDS LIMIT ${total > EFFECTIVE}`);
