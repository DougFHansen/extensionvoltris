#!/usr/bin/env node
/**
 * Generates a compact Public Suffix List trie used by the extension at runtime.
 *
 * Why generate instead of bundling a library:
 *  - The PSL is DATA (MPL-2.0), not code. Shipping a generated trie keeps the
 *    extension dependency-free at runtime and keeps the shipped surface small.
 *  - The full list is vendored in `vendor/public_suffix_list.dat` so builds are
 *    reproducible and auditable offline. Refresh with `npm run psl -- --update`.
 *
 * Output: src/generated/psl.json
 *
 * Trie encoding (keys are labels, stored TLD-first):
 *   1                       -> terminal node: this label is itself a rule
 *   { "$": 1, <label>: ... } -> node that is a rule ("$") and/or has children
 *   key "*"                 -> wildcard rule: matches any single label
 *   key "!"                 -> exception rule: prevailing suffix is one label shorter
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, copyFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const PSL_URL = 'https://publicsuffix.org/list/public_suffix_list.dat';
const VENDORED = resolve(ROOT, 'vendor', 'public_suffix_list.dat');
const OUT = resolve(ROOT, 'src', 'generated', 'psl.json');

async function obtainList() {
  const update = process.argv.includes('--update');
  if (!update && existsSync(VENDORED)) {
    return { text: readFileSync(VENDORED, 'utf8'), origin: 'vendored' };
  }
  process.stdout.write(`[psl] downloading ${PSL_URL}\n`);
  const res = await fetch(PSL_URL, { headers: { 'user-agent': 'voltris-browser-shield-build' } });
  if (!res.ok) {
    if (existsSync(VENDORED)) {
      process.stdout.write(`[psl] download failed (${res.status}); using vendored copy\n`);
      return { text: readFileSync(VENDORED, 'utf8'), origin: 'vendored-fallback' };
    }
    throw new Error(`Failed to download PSL: HTTP ${res.status}`);
  }
  const text = await res.text();
  mkdirSync(dirname(VENDORED), { recursive: true });
  writeFileSync(VENDORED, text, 'utf8');
  return { text, origin: 'download' };
}

function parseRules(source) {
  const normal = [];
  const wildcard = [];
  const exceptions = [];
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    if (line.startsWith('//')) continue;
    if (line.startsWith('!')) {
      exceptions.push(line.slice(1).toLowerCase());
    } else if (line.startsWith('*.')) {
      wildcard.push(line.slice(2).toLowerCase());
    } else {
      normal.push(line.toLowerCase());
    }
  }
  return { normal, wildcard, exceptions };
}

/**
 * Inserts one rule into the trie, stored TLD-first.
 *
 * The trie is keyed from the TLD down, so the LEFTMOST label of a rule ends up
 * at the DEEPEST level. Encoding:
 *   `com`          -> root.com.$ = 1
 *   `*.ck`         -> root.ck['*'].$ = 1          (wildcard consumes one label)
 *   `!www.ck`      -> root.ck.www['!'] = 1       (exception keeps its real label)
 *
 * The exception marker lives ON the node for its own leftmost label rather than
 * replacing it, so `!www.ck` can never accidentally match `foo.ck`.
 */
function insert(root, rule, { wildcard = false, exception = false } = {}) {
  const labels = wildcard ? ['*', ...rule.split('.')] : rule.split('.');
  let node = root;
  for (let i = labels.length - 1; i >= 0; i -= 1) {
    const label = labels[i];
    if (wildcard && label === '*') {
      // The wildcard stands for one arbitrary label, stored as a literal `*` child.
    }
    let child = node[label];
    if (child === undefined) {
      child = {};
      node[label] = child;
    }
    if (child === 1) {
      // A bare terminal already marks this node as a rule; it can also have
      // children (for example `uk` is a rule and also contains `co`).
      child = { $: 1 };
      node[label] = child;
    }
    node = child;
  }
  node[exception ? '!' : '$'] = 1;
}

function buildTrie(parsed) {
  const root = {};
  for (const rule of parsed.normal) insert(root, rule);
  for (const rule of parsed.wildcard) insert(root, rule, { wildcard: true });
  for (const rule of parsed.exceptions) insert(root, rule, { exception: true });
  return root;
}

async function main() {
  const { text, origin } = await obtainList();
  const sha256 = createHash('sha256').update(text, 'utf8').digest('hex');
  const parsed = parseRules(text);
  const trie = buildTrie(parsed);

  // DETERMINISTIC OUTPUT.
  //
  // `generatedAt` used to be `new Date().toISOString()`, which meant every build
  // rewrote the committed psl.json even when the Public Suffix List had not
  // changed at all - producing a spurious diff on a 187 KB generated file and
  // changing the published package's SHA-256 for no reason.
  //
  // The date is now taken from the source list's own modification date, so the
  // same input always produces byte-identical output. When a build reuses the
  // already-vendored copy (the normal case) that date is the vendoring date,
  // which is the honest answer to "when did we take this snapshot".
  const generatedAt = new Date(statSync(VENDORED).mtimeMs).toISOString();

  const payload = {
    schemaVersion: 1,
    source: PSL_URL,
    license: 'MPL-2.0',
    licenseUrl: 'https://mozilla.org/MPL/2.0/',
    origin,
    sha256,
    generatedAt,
    ruleCount: parsed.normal.length + parsed.wildcard.length + parsed.exceptions.length,
    icannRules: parsed.normal.length,
    privateRules: parsed.wildcard.length + parsed.exceptions.length,
    root: trie,
  };
  mkdirSync(dirname(OUT), { recursive: true });

  const next = `${JSON.stringify(payload)}\n`;
  // Only write when the content actually differs, so mtime stays stable and git
  // does not see a change on every build.
  if (!existsSync(OUT) || readFileSync(OUT, 'utf8') !== next) writeFileSync(OUT, next, 'utf8');

  const size = Buffer.byteLength(next);
  process.stdout.write(
    `[psl] ${payload.ruleCount} rules (${origin}) -> src/generated/psl.json (${(size / 1024).toFixed(1)} KiB, sha256 ${sha256.slice(0, 12)})\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`[psl] ERROR ${err && err.message ? err.message : String(err)}\n`);
  process.exit(1);
});
