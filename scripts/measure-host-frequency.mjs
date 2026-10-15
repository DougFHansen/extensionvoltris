/**
 * Does filter FREQUENCY identify the ad hosts that matter?
 *
 * A uniform 2% sample of EasyList cannot reliably contain any particular host:
 * `static.doubleclick.net` sits at 79.6% of the list, so a uniform sample almost
 * never reaches it. If a host appears in many filters, that is a usable signal
 * for which hosts deserve the scarce rule budget.
 */
import fs from 'node:fs';

const text = fs.readFileSync('C:/Users/VOLTRIS/AppData/Local/Temp/opencode/feeds/easylist.txt', 'utf8');

/** Counts how many distinct filters mention each host, mirroring the real parser. */
const counts = new Map();
for (const rawLine of text.split(/\r?\n/)) {
  const line = rawLine.trim();
  if (line === '' || line.startsWith('!') || line.startsWith('#')) continue;
  if (line.includes('##')) continue; // cosmetic
  if (line.startsWith('/') && line.endsWith('/')) continue;

  const optionsAt = line.indexOf('$');
  const pattern = optionsAt >= 0 ? line.slice(0, optionsAt) : line;
  const m = pattern.match(/^\|\|([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/i);
  if (!m) continue;
  const host = m[1].toLowerCase();
  counts.set(host, (counts.get(host) ?? 0) + 1);
}

const total = counts.size;
console.log(`distinct hosts in easylist: ${total}\n`);

const ranked = [...counts].sort((a, b) => b[1] - a[1]);

console.log("=== top 25 hosts by filter frequency ===");
for (const [host, n] of ranked.slice(0, 25)) console.log(`  ${String(n).padStart(4)}  ${host}`);

console.log("\n=== frequency of the ad hosts seen on a real page ===");
for (const host of [
  'static.doubleclick.net',
  'pagead2.googlesyndication.com',
  'googlesyndication.com',
  'doubleclick.net',
  'googletagmanager.com',
  'googleadservices.com',
  'adnxs.com',
  'criteo.com',
  'taboola.com',
  'adservice.google.com',
]) {
  console.log(`  ${String(counts.get(host) ?? 0).padStart(4)}  ${host}`);
}

// Would a frequency-ranked top-N have covered them?
const N = 2_500;
const top = new Set(ranked.slice(0, N).map(([h]) => h));
console.log(`\n=== would a top-${N} frequency ranking cover them? ===`);
for (const host of ['static.doubleclick.net', 'pagead2.googlesyndication.com', 'googlesyndication.com', 'googletagmanager.com']) {
  console.log(`  ${top.has(host) ? 'COVERED' : 'missing'}  ${host}`);
}

// How much of the list does the frequency threshold of >=2 represent?
const multi = [...counts].filter(([, n]) => n >= 2).length;
console.log(`\nhosts appearing in 2+ filters: ${multi} (${((multi / total) * 100).toFixed(1)}% of hosts)`);
console.log(`hosts appearing in 3+ filters: ${[...counts].filter(([, n]) => n >= 3).length}`);
