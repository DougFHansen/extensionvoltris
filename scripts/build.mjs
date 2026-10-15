#!/usr/bin/env node
/**
 * Build orchestrator.
 *
 * Produces `dist/chrome` and `dist/edge`.
 *
 * Build strategy and why:
 *  - The service worker and the content script are each emitted as ONE
 *    self-contained IIFE file. Content scripts cannot use ES module imports, and
 *    a chunk-free service worker removes an entire class of "worker suspended
 *    while fetching a chunk" failure modes.
 *  - The four UI pages are emitted as ES modules and may share chunks. Strict
 *    CSP `script-src 'self'` permits relative imports, and code splitting keeps
 *    the popup payload small.
 *  - CSS and HTML are COPIED, not processed. Every stylesheet is already a plain
 *    static file linked from the page, which keeps the output deterministic and
 *    makes the shipped HTML readable in a store review.
 */
import { build } from 'vite';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const SRC = resolve(ROOT, 'src');
const DIST = resolve(ROOT, 'dist');

const TARGETS = ['chrome', 'edge'];

const SELF_CONTAINED = [
  { name: 'background', input: resolve(SRC, 'background/service-worker.ts'), file: 'background.js' },
  { name: 'content', input: resolve(SRC, 'content/content.ts'), file: 'content.js' },
];

const PAGES = [
  { name: 'popup', input: resolve(SRC, 'ui/popup/popup.ts'), file: 'popup.js', html: 'ui/popup/popup.html' },
  { name: 'dashboard', input: resolve(SRC, 'ui/dashboard/dashboard.ts'), file: 'dashboard.js', html: 'ui/dashboard/dashboard.html' },
  { name: 'options', input: resolve(SRC, 'ui/options/options.ts'), file: 'options.js', html: 'ui/options/options.html' },
  { name: 'blocked', input: resolve(SRC, 'ui/blocked/blocked.ts'), file: 'blocked.js', html: 'ui/blocked/blocked.html' },
];

/**
 * Per-target manifest differences.
 *
 * These are REAL differences, not cosmetic ones:
 *  - `minimum_chrome_version` is a Chrome Web Store field. The Edge Add-ons
 *    platform ignores it and does not need it, so the Edge build omits it.
 *  - The name gets a store suffix only if a channel build is requested
 *    (`--channel=beta`), which keeps release builds byte-identical.
 */
function buildManifest(target, channel) {
  const base = JSON.parse(readFileSync(resolve(SRC, 'manifest.json'), 'utf8'));
  const manifest = { ...base };

  if (target === 'edge') {
    delete manifest.minimum_chrome_version;
  }

  if (channel && channel !== 'stable') {
    manifest.name = `${manifest.name} (${channel})`;
    manifest.version = `${manifest.version}.${Date.now() % 1000}`;
  }

  return manifest;
}

async function buildSelfContained(outDir) {
  for (const target of SELF_CONTAINED) {
    await build({
      root: ROOT,
      logLevel: 'warn',
      configFile: false,
      define: { __VBS_TARGET__: JSON.stringify('stable') },
      build: {
        outDir,
        emptyOutDir: false,
        target: 'chrome120',
        minify: 'oxc',
        sourcemap: false,
        cssCodeSplit: false,
        lib: {
          entry: target.input,
          formats: ['iife'],
          name: `vbs_${target.name}`,
          fileName: () => target.file,
        },
      },
    });
  }
}

async function buildPages(outDir) {
  const input = {};
  const fileNames = {};
  for (const page of PAGES) {
    input[page.name] = page.input;
    fileNames[page.name] = page.file;
  }

  await build({
    root: ROOT,
    logLevel: 'warn',
    configFile: false,
    build: {
      outDir,
      emptyOutDir: false,
      target: 'chrome120',
      minify: 'oxc',
      sourcemap: false,
      modulePreload: { polyfill: false },
      rollupOptions: {
        input,
        output: {
          format: 'es',
          entryFileNames: (chunk) => fileNames[chunk.name] ?? `${chunk.name}.js`,
          chunkFileNames: 'chunks/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash][extname]',
        },
      },
    },
  });
}

function copyStatic(outDir) {
  cpSync(resolve(SRC, '_locales'), join(outDir, '_locales'), { recursive: true });
  cpSync(resolve(SRC, 'assets'), join(outDir, 'assets'), { recursive: true });
  cpSync(resolve(SRC, 'ui/styles'), join(outDir, 'styles'), { recursive: true });

  for (const page of PAGES) {
    cpSync(resolve(SRC, page.html), join(outDir, pathBasename(page.html)));
  }

  const psl = resolve(SRC, 'generated/psl.json');
  if (!existsSync(psl)) {
    throw new Error('Missing src/generated/psl.json - run `npm run psl` first.');
  }
  cpSync(psl, join(outDir, 'psl.json'));

  // Ship the privacy policy inside the package so the link in
  // Settings -> About works offline and reviewers can read it from the archive.
  const privacy = resolve(ROOT, 'PRIVACY.md');
  if (existsSync(privacy)) cpSync(privacy, join(outDir, 'PRIVACY.md'));
}

function pathBasename(p) {
  return p.split('/').pop();
}

function dirSize(dir) {
  let total = 0;
  for (const entry of walk(dir)) total += statSync(entry).size;
  return total;
}

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else yield full;
  }
}

function countFiles(dir) {
  let n = 0;
  for (const _ of walk(dir)) n += 1;
  return n;
}

async function main() {
  const channelArg = process.argv.find((a) => a.startsWith('--channel='));
  const channel = channelArg ? channelArg.split('=')[1] : 'stable';

  rmSync(DIST, { recursive: true, force: true });
  mkdirSync(DIST, { recursive: true });

  for (const target of TARGETS) {
    const outDir = join(DIST, target);
    mkdirSync(outDir, { recursive: true });

    await buildSelfContained(outDir);
    await buildPages(outDir);
    copyStatic(outDir);

    const manifest = buildManifest(target, channel);
    writeFileSync(join(outDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    const bytes = dirSize(outDir);
    process.stdout.write(
      `[build] dist/${target}: ${(bytes / 1024).toFixed(0)} KiB across ${countFiles(outDir)} files\n`,
    );
  }

  process.stdout.write('[build] done\n');
}


main().catch((error) => {
  process.stderr.write(`[build] ERROR ${error?.stack ?? String(error)}\n`);
  process.exit(1);
});
