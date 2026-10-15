#!/usr/bin/env node
/**
 * Static analysis gate.
 *
 * Runs against the BUILT extension in `dist/`, not just the sources, so it also
 * catches anything a bundler might have pulled in. Fails the build on any
 * finding.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const ALLOWED_PERMISSIONS = new Set([
  'storage',
  'alarms',
  'declarativeNetRequest',
  // Observes a failed top-level navigation so a block can be counted and
  // explained. Available to published extensions and carries no install-time
  // warning. This REPLACED `declarativeNetRequestFeedback`, whose API is
  // documented as unpacked-only; see src/background/observation.ts.
  'webNavigation',
  'downloads',
  'notifications',
  'scripting',
  // Displays the current site's icon from the browser's own favicon cache.
  // No request leaves the browser; no install-time warning.
  'favicon',
  // Lifts the 10 MB storage.local quota. The packed threat dataset measures
  // ~27 MiB against the real feeds, so without this the extension cannot store
  // the threat data at all. The permission grants no access to anything the user
  // holds; it only removes a size ceiling, and Chrome shows no install warning.
  'unlimitedStorage',
  'activeTab',
]);

/**
 * Permissions that exist only to feed a development build.
 *
 * `declarativeNetRequestFeedback` gates `onRuleMatchedDebug` and
 * `getMatchedRules()`, both documented as unpacked-only. Shipping it would buy
 * nothing in a store install.
 */
const DEV_ONLY_PERMISSIONS = new Set(['declarativeNetRequestFeedback', 'declarativeNetRequestWithHostAccess']);

/**
 * API symbols documented as available only to unpacked extensions.
 *
 * Their presence in a built package means production code still expects a
 * signal that will never arrive after a store install.
 */
const DEV_ONLY_API_NAMES = ['onRuleMatchedDebug', 'getMatchedRules', 'declarativeNetRequestFeedback'];

const FORBIDDEN_PERMISSIONS = new Set([
  'cookies', 'history', 'webRequest', 'webRequestBlocking', 'management',
  'nativeMessaging', 'privacy', 'identity', 'proxy', 'debugger',
  'clipboardRead', 'clipboardWrite', 'browsingData', 'desktopCapture',
  'pageCapture', 'sessions', 'system.display',
]);

const FORBIDDEN_PATTERNS = [
  { re: /\beval\s*\(/, label: 'eval()' },
  { re: /new\s+Function\s*\(/, label: 'Function constructor' },
  { re: /\.innerHTML\s*=/, label: 'innerHTML assignment' },
  { re: /\.outerHTML\s*=/, label: 'outerHTML assignment' },
  { re: /insertAdjacentHTML/, label: 'insertAdjacentHTML' },
  { re: /document\.write/, label: 'document.write' },
  { re: /set\s*Timeout\s*\(\s*[`'"]/, label: 'eval-like setTimeout' },
  { re: /importScripts\s*\(/, label: 'importScripts (remote code)' },
];

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const findings = [];
const notes = [];

function fail(where, message) {
  findings.push({ where, message });
}

function main() {
  const targets = ['dist/chrome', 'dist/edge'].filter((d) => existsSync(resolve(ROOT, d)));
  if (targets.length === 0) {
    fail('build', 'No dist/ directory found. Run `npm run build` first.');
    report();
    return;
  }

  for (const target of targets) {
    const dir = resolve(ROOT, target);
    const manifestPath = join(dir, 'manifest.json');
    if (!existsSync(manifestPath)) {
      fail(target, 'manifest.json missing');
      continue;
    }

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const label = `${target}/manifest.json`;

    // --- manifest shape
    if (manifest.manifest_version !== 3) fail(label, 'manifest_version must be 3');
    if (!manifest.default_locale) fail(label, 'default_locale is required for _locales');
    if (manifest.externally_connectable) fail(label, 'externally_connectable must not be declared');
    if (manifest.web_accessible_resources) {
      notes.push(`${label}: web_accessible_resources present (${JSON.stringify(manifest.web_accessible_resources)})`);
    }

    // --- CSP
    const csp = manifest.content_security_policy?.extension_pages ?? '';
    if (!csp.includes("script-src 'self'")) fail(label, "CSP must contain script-src 'self'");
    if (csp.includes('unsafe-eval') || csp.includes('unsafe-inline')) fail(label, 'CSP must not allow unsafe-eval/unsafe-inline');
    if (manifest.sandbox?.pages) fail(label, 'sandboxed pages could weaken the extension');

    // --- permissions
    for (const permission of manifest.permissions ?? []) {
      if (FORBIDDEN_PERMISSIONS.has(permission)) fail(label, `forbidden permission: ${permission}`);
      if (DEV_ONLY_PERMISSIONS.has(permission)) {
        fail(label, `development-only permission in a published package: ${permission}`);
      }
      if (!ALLOWED_PERMISSIONS.has(permission)) fail(label, `unrecognised permission: ${permission}`);
    }
    for (const permission of manifest.optional_permissions ?? []) {
      if (FORBIDDEN_PERMISSIONS.has(permission)) fail(label, `forbidden optional permission: ${permission}`);
    }

    // --- every referenced file must exist
    const referenced = [
      manifest.background?.service_worker,
      manifest.action?.default_popup,
      ...Object.values(manifest.icons ?? {}),
      ...Object.values(manifest.action?.default_icon ?? {}),
      ...(manifest.content_scripts ?? []).flatMap((cs) => cs.js ?? []),
    ].filter(Boolean);
    for (const file of referenced) {
      if (!existsSync(join(dir, file))) fail(label, `referenced file missing: ${file}`);
    }

    // --- locales
    for (const locale of ['en', 'pt_BR']) {
      if (!existsSync(join(dir, '_locales', locale, 'messages.json'))) fail(label, `missing locale ${locale}`);
    }

    // --- payload analysis
    const jsFiles = walk(dir).filter((f) => f.endsWith('.js'));
    if (jsFiles.length === 0) fail(target, 'no JavaScript emitted');

    // --- absolute URLs in the shipped payload
    /**
     * Hosts allowed to appear as literals in the shipped payload.
     *
     * This is a REVIEW list, not a fetch allowlist. A host appearing here does
     * not mean we contact it - it means the string is expected to be present
     * (feed URL, licence link, provider homepage shown in the UI, or an XML
     * namespace URI that is never dereferenced). The updater still refuses any
     * feed URL that is not `https:` and not declared in the registry.
     */
    const EXPECTED_HOSTS = new Set([
      // Feed endpoints actually downloaded (all HTTPS, all in the registry)
      'raw.githubusercontent.com',
      'easylist.to',
      'publicsuffix.org',
      'data.phishtank.com',
      'urlhaus-api.abuse.ch',
      // Provider homepages and licence pages rendered as links in the UI
      'urlhaus.abuse.ch',
      'github.com',
      'phishtank.org',
      'openphish.com',
      'mozilla.org',
      'developer.chrome.com',
      'chrome.google.com',
      'chromewebstore.google.com',
      'microsoftedge.microsoft.com',
      // W3C namespace URIs required by DOM APIs. Never dereferenced.
      'www.w3.org',
    ]);

    for (const file of jsFiles) {
      const code = readFileSync(file, 'utf8');
      const rel = relative(ROOT, file);
      for (const { re, label: patternLabel } of FORBIDDEN_PATTERNS) {
        if (re.test(code)) fail(rel, `forbidden pattern: ${patternLabel}`);
      }
      // The shipped bundle must contain no reference to the matched-rule feed.
      // It does not exist in a published extension, so any surviving call site
      // would be a silent no-op in production - exactly the fault this check
      // was written for.
      for (const needle of DEV_ONLY_API_NAMES) {
        if (code.includes(needle)) fail(rel, `development-only API referenced in shipped code: ${needle}`);
      }
      for (const match of code.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
        const host = match[1].toLowerCase();
        if (!EXPECTED_HOSTS.has(host)) {
          fail(rel, `unexpected remote host in shipped payload: ${host}`);
        }
      }
    }

    // --- size budget
    const total = walk(dir).reduce((sum, f) => sum + statSync(f).size, 0);
    const mb = total / 1024 / 1024;
    if (mb > 12) fail(target, `package is ${mb.toFixed(1)} MiB; Chrome Web Store expects well under this`);
    notes.push(`${target}: ${(total / 1024).toFixed(0)} KiB across ${walk(dir).length} files`);

    // --- no remote scripts referenced from HTML
    for (const file of walk(dir).filter((f) => f.endsWith('.html'))) {
      const html = readFileSync(file, 'utf8');
      const rel = relative(ROOT, file);
      if (/<script[^>]+src\s*=\s*["']https?:/i.test(html)) fail(rel, 'HTML loads a remote script');
      if (/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?\S[\s\S]*?<\/script>/i.test(html)) {
        fail(rel, 'HTML contains an inline <script> (forbidden by MV3)');
      }
    }
  }

  report();
}

function report() {
  for (const note of notes) process.stdout.write(`  note  ${note}\n`);

  if (findings.length > 0) {
    process.stderr.write('\n[static-analysis] FAILED\n');
    for (const f of findings) process.stderr.write(`  ${f.where}: ${f.message}\n`);
    process.exit(1);
  }

  process.stdout.write('\n[static-analysis] passed: no forbidden patterns, permissions or CSP issues\n');
}

main();
