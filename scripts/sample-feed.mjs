/**
 * Picks a realistic slice of each live feed, ordered as the feed orders it, so
 * the committed snapshot resembles what a user's install actually contains.
 *
 * EasyList and friends are sorted ASCII, so a naive slice keeps only domains
 * beginning with a few letters. This samples across the alphabet instead.
 *
 * Usage: npx tsx scripts/sample-feed.mjs <list.txt> <count>
 */
import fs from 'node:fs';

const [, , file, countArg] = process.argv;
const count = Number(countArg ?? 3000);

const hosts = fs
  .readFileSync(file, 'utf8')
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter((l) => /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(l) && !l.startsWith('0.'));

const unique = [...new Set(hosts)].sort();
if (unique.length === 0) {
  console.error('no hosts parsed');
  process.exit(1);
}

// Even stride across the whole list, so every part of the alphabet is represented.
const step = unique.length / count;
const picked = [];
for (let i = 0; i < count; i += 1) picked.push(unique[Math.floor(i * step)]);

process.stdout.write(`${picked.join('\n')}\n`);
