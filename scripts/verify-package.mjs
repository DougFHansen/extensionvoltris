/**
 * Loads the PACKAGED archive (not `dist/`) into a real Chromium.
 *
 * `npm run test:e2e` proves the build works. This proves the artifact that gets
 * uploaded to the stores is the same working thing. A packaging defect - wrong
 * separators, a missing file, a mangled path - is invisible to every other check
 * and only surfaces when the browser refuses to load the extension.
 *
 * The archive is extracted with .NET rather than by hand, so the check uses an
 * independent ZIP implementation: if our writer and a foreign reader disagree,
 * this is where it shows. Chromium's `--load-extension` takes a directory, not an
 * archive, so extraction is required to run it at all.
 */
import { existsSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { chromium } from '@playwright/test';

const version = JSON.parse(readFileSync('src/manifest.json', 'utf8')).version;
const zip = resolve(`artifacts/voltris-browser-shield-${version}-chrome.zip`);

if (!existsSync(zip)) {
  console.error(`missing ${zip} - run: npm run build && npm run package`);
  process.exit(1);
}

const work = mkdtempSync(join(tmpdir(), 'vbs-zip-'));
const unpacked = join(work, 'extension');
let failed = false;

/**
 * Extracts the archive with a reader we did not write.
 *
 * The point is independence: if our ZIP writer and a foreign implementation
 * disagree about the format, this is where it shows. On Windows that reader is
 * .NET's `ZipFile`; elsewhere it is the `unzip` binary.
 */
function extractIndependently(archive, destination) {
  if (process.platform === 'win32') {
    execFileSync(
      'powershell',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        'Add-Type -AssemblyName System.IO.Compression.FileSystem; ' +
          `[System.IO.Compression.ZipFile]::ExtractToDirectory('${archive}', '${destination}')`,
      ],
      { stdio: 'inherit' },
    );
    return '.NET ZipFile';
  }

  execFileSync('unzip', ['-q', '-o', archive, '-d', destination], { stdio: 'inherit' });
  return 'unzip';
}

try {
  const reader = extractIndependently(zip, unpacked);
  console.log(`[zip-verify] archive extracted with ${reader} (independent reader)`);

  const ctx = await chromium.launchPersistentContext(join(work, 'profile'), {
    channel: 'chromium',
    headless: true,
    args: [
      `--disable-extensions-except=${unpacked}`,
      `--load-extension=${unpacked}`,
      '--lang=en-US',
      '--no-sandbox',
      '--disable-gpu',
    ],
  });

  const worker = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker', { timeout: 30_000 }));
  const id = new URL(worker.url()).host;

  // The worker only starts when the browser considers the extension valid, so
  // reaching this line already proves the extracted package was accepted.
  const manifest = await worker.evaluate(() => chrome.runtime.getManifest());
  console.log(`[zip-verify] extension id      ${id}`);
  console.log(`[zip-verify] name              ${manifest.name}`);
  console.log(`[zip-verify] version           ${manifest.version}`);
  console.log(`[zip-verify] permissions       ${manifest.permissions.join(', ')}`);

  const rules = await worker.evaluate(async () => (await chrome.declarativeNetRequest.getDynamicRules()).length);
  console.log(`[zip-verify] dynamic rules     ${rules}`);

  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${id}/popup.html`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('.popup-top', { timeout: 20_000 });
  console.log(`[zip-verify] popup renders     yes ("${await page.title()}")`);
  await page.close();

  await ctx.close();
} catch (error) {
  failed = true;
  console.error('[zip-verify] FAILED:', error instanceof Error ? error.message : String(error));
} finally {
  // Best effort: Chromium can still hold the profile briefly after closing, and
  // a locked temp directory must never mask the actual verification result.
  try {
    rmSync(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
  } catch {
    /* left behind in the OS temp directory; harmless */
  }
}

console.log(failed ? '\n[zip-verify] packaged archive does NOT load' : '\n[zip-verify] packaged archive loads and runs');
process.exit(failed ? 1 : 0);
