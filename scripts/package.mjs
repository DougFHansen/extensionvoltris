#!/usr/bin/env node
/**
 * Produces the store-ready archives.
 *
 * The archive is written by `scripts/lib/zip.mjs` rather than by the OS
 * compressor. PowerShell's `Compress-Archive` on Windows PowerShell 5.1 stores
 * `\` as the path separator, which violates APPNOTE 4.4.17.1 and produced a
 * package the Chrome Web Store could not read. Writing the ZIP ourselves makes
 * the output identical on every platform and verifiable.
 *
 * The archive is read back and checked before it is reported as successful, so a
 * packaging defect fails here rather than during review.
 *
 * Layout produced under `artifacts/`:
 *   voltris-browser-shield-<version>-chrome.zip
 *   voltris-browser-shield-<version>-edge.zip
 *   SHA256SUMS.txt
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative, resolve, dirname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createZip, listZipEntries } from './lib/zip.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = resolve(ROOT, 'dist');
const OUT = resolve(ROOT, 'artifacts');
const TARGETS = ['chrome', 'edge'];

/** Files that must sit at the archive root for the browser to find them. */
const REQUIRED_AT_ROOT = ['manifest.json'];

function version() {
  const manifest = JSON.parse(readFileSync(resolve(DIST, 'chrome', 'manifest.json'), 'utf8'));
  return manifest.version ?? '0.0.0';
}

/** Collects files as ZIP entries, converting separators to the required `/`. */
function collect(sourceDir) {
  const entries = [];
  const walk = (dir) => {
    for (const item of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const full = join(dir, item.name);
      if (item.isDirectory()) {
        walk(full);
        continue;
      }
      const stat = statSync(full);
      entries.push({
        // relative() yields backslashes on Windows; the archive must not.
        name: relative(sourceDir, full).split(sep).join('/'),
        data: readFileSync(full),
        mtime: stat.mtimeMs,
        mode: stat.mode,
      });
    }
  };
  walk(sourceDir);
  return entries;
}

/**
 * Re-reads the produced archive and checks it against the source directory.
 *
 * This is the step that would have caught the backslash bug. It is deliberately
 * paranoid: a store upload that fails costs days, and the error a store returns
 * for a malformed package rarely identifies the cause.
 */
function verifyArchive(archive, entries, label) {
  const problems = [];
  const names = listZipEntries(archive);

  const backslashed = names.filter((n) => n.includes('\\'));
  if (backslashed.length > 0) problems.push(`entries use "\\" separators (spec requires "/"): ${backslashed[0]}`);

  for (const required of REQUIRED_AT_ROOT) {
    if (!names.includes(required)) problems.push(`missing required root file: ${required}`);
  }

  if (names.length !== entries.length) {
    problems.push(`entry count mismatch: archive has ${names.length}, source has ${entries.length}`);
  }

  const unsafe = names.filter((n) => n.startsWith('/') || n.split('/').includes('..') || /^[A-Za-z]:/.test(n));
  if (unsafe.length > 0) problems.push(`non-relative or traversing entry path: ${unsafe[0]}`);

  if (problems.length > 0) {
    process.stderr.write(`[package] ${label} FAILED verification:\n`);
    for (const p of problems) process.stderr.write(`  - ${p}\n`);
    process.exit(1);
  }
  return names.length;
}

function dirSize(dir) {
  let total = 0;
  const walk = (d) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else total += statSync(full).size;
    }
  };
  walk(dir);
  return total;
}

function main() {
  if (!existsSync(DIST)) {
    process.stderr.write('[package] dist/ not found. Run `npm run build` first.\n');
    process.exit(1);
  }

  mkdirSync(OUT, { recursive: true });
  const v = version();
  const sums = [];

  for (const target of TARGETS) {
    const sourceDir = join(DIST, target);
    if (!existsSync(sourceDir)) {
      process.stderr.write(`[package] dist/${target} not found. Skipping.\n`);
      continue;
    }

    const entries = collect(sourceDir);
    const archive = createZip(entries);

    const outFile = join(OUT, `voltris-browser-shield-${v}-${target}.zip`);
    writeFileSync(outFile, archive);

    const label = `${target}.zip`;
    const count = verifyArchive(archive, entries, label);

    const hash = createHash('sha256').update(archive).digest('hex');
    const name = outFile.split(/[\\/]/).pop();
    sums.push(`${hash}  ${name}`);

    process.stdout.write(
      `[package] ${name}  ${(archive.length / 1024).toFixed(0)} KiB  ` +
        `(unpacked ${(dirSize(sourceDir) / 1024).toFixed(0)} KiB, ${count} entries)\n`,
    );
    process.stdout.write(`[package]   verified: manifest.json at root, ${count} entries, "/" separators, sha256 ${hash}\n`);
  }

  writeFileSync(join(OUT, 'SHA256SUMS.txt'), `${sums.join('\n')}\n`, 'utf8');
  process.stdout.write('[package] artifacts/SHA256SUMS.txt written\n');
}

main();
