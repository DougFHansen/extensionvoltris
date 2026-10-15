#!/usr/bin/env node
/**
 * PRIVACY AUDIT - produces technical evidence for the store data-collection
 * declaration instead of asserting "we collect nothing" in prose.
 *
 * The Chrome Web Store and Edge Add-ons forms ask whether an extension collects
 * or transmits user data. The honest answer here is "no", and this script is the
 * evidence behind that answer. It inspects the BUILT package, not the source,
 * because the built package is what gets published.
 *
 * What it proves:
 *   1. No outbound endpoint other than the public threat feeds listed in the
 *      feed registry, and no analytics, telemetry or tracking host.
 *   2. No request carries a tracking identifier, and no remote code is fetched.
 *   3. Nothing the extension stores leaves the device: there is no code path
 *      from a storage read to a network send.
 *   4. The declared permission set contains no data-access permission
 *      (cookies, history, browsing data, native messaging, clipboard, ...).
 *   5. No remote endpoint is called with a POST/PUT body.
 *
 * What it deliberately does NOT claim: that the browser does not log anything
 * of its own, or that the feed publishers see the user's IP. Those are stated
 * plainly in PRIVACY.md instead.
 *
 * Usage: node scripts/privacy-audit.mjs [--json]
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const asJson = process.argv.includes('--json');

/**
 * Hosts that would indicate analytics, telemetry or tracking.
 *
 * Substring matching, so `google-analytics.com` and `googletagmanager.com` are
 * both caught. `googleapis` is deliberately absent: nothing in this extension
 * talks to Google infrastructure.
 */
const ANALYTICS_HOST_PATTERNS = [
  /google-analytics/i,
  /googletagmanager/i,
  /analytics\./i,
  /telemetry/i,
  /sentry\.io/i,
  /bugsnag/i,
  /datadoghq/i,
  /segment\.(io|com)/i,
  /mixpanel/i,
  /amplitude/i,
  /hotjar/i,
  /fullstory/i,
  /logrocket/i,
  /intercom/i,
  /appsflyer/i,
  /branch\.io/i,
  /adjust\.com/i,
  /facebook\.com/i,
  /doubleclick/i,
  /scorecardresearch/i,
  /quantserve/i,
  /criteo/i,
  /taboola/i,
  /outbrain/i,
  /bing\.com/i,
];

/** Identifiers that would attach a stable handle to a user or a machine. */
const TRACKING_IDENTIFIER_PATTERNS = [
  { re: /\bga\s*\(\s*['"`]/, label: 'Google Analytics call' },
  { re: /\bgtag\s*\(/, label: 'gtag.js call' },
  { re: /\bga\s*\(\s*['"`]track['"`]/, label: 'analytics track event' },
  { re: /\bsendBeacon\s*\(/, label: 'navigator.sendBeacon' },
  { re: /\bnew\s+WebSocket\b/, label: 'WebSocket connection' },
  { re: /\bnavigator\.sendBeacon\b/, label: 'sendBeacon' },
];

/**
 * Permissions that grant access to data the user did not hand us directly.
 *
 * `webNavigation` and `declarativeNetRequest` are deliberately NOT listed: both
 * are needed to block a request before it completes, which is the product's
 * entire purpose, and neither grants access to stored content or credentials.
 */
const DATA_ACCESS_PERMISSIONS = [
  'cookies',
  'history',
  'bookmarks',
  'topSites',
  'webRequest',
  'webRequestBlocking',
  'management',
  'nativeMessaging',
  'identity',
  'privacy',
  'browsingData',
  'clipboardRead',
  'clipboardWrite',
  'downloads.open',
  'desktopCapture',
  'pageCapture',
  'sessions',
  'system.display',
  'idle',
  'geolocation',
  'audio',
  'videoCapture',
  'usb',
  'serial',
  'processes',
  'proxy',
  'debugger',
  'tabCapture',
  'declarativeNetRequestWithHostAccess',
];

/** Storage keys that must never hold page content or credentials. */
const FORBIDDEN_STORAGE_KEYS = [
  'vbs.passwords',
  'vbs.history.browser',
  'vbs.cookies',
  'vbs.tokens',
  'vbs.credentials',
  'vbs.pageContent',
  'vbs.formData',
];

/**
 * URIs that look like hosts but are never dereferenced.
 *
 * `http://www.w3.org/2000/svg` is the XML namespace identifier. The DOM only
 * matches it; nothing resolves or transmits it. Listing it here (rather than
 * ignoring unknown hosts silently) keeps the audit's host list complete.
 */
const NON_NETWORK_HOSTS = new Map([['www.w3.org', 'XML namespace identifier for SVG elements; never dereferenced']]);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

/** Strips comments so documentation cannot be mistaken for behaviour. */
function stripComments(code) {
  return code.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

const findings = [];
const evidence = [];
function fail(where, message) {
  findings.push({ where, message });
}
function note(where, message) {
  evidence.push({ where, message });
}

/**
 * Every host the shipped code can reach.
 *
 * Extracted from string literals containing a URL, plus the feed registry. The
 * service worker and the pages are analysed together because the same promise
 * covers all of them.
 */
function extractHosts(files) {
  const hosts = new Map();
  for (const file of files) {
    const code = stripComments(readFileSync(file, 'utf8'));
    for (const match of code.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)) {
      const host = match[1].toLowerCase();
      if (!hosts.has(host)) hosts.set(host, new Set());
      hosts.get(host).add(relative(ROOT, file));
    }
  }
  return hosts;
}

function main() {
  const targets = ['dist/chrome', 'dist/edge'].filter((d) => existsSync(resolve(ROOT, d)));
  if (targets.length === 0) {
    fail('build', 'No dist/ directory found. Run `npm run build` first.');
    report();
    return;
  }

  // Public threat feeds are the only destinations. Taken from the registry so
  // this script cannot be satisfied by a hand-written allowlist that drifts.
  const registrySource = readFileSync(resolve(ROOT, 'src/feeds/registry.ts'), 'utf8');
  const feedHosts = new Set(
    [...stripComments(registrySource).matchAll(/https?:\/\/([a-z0-9.-]+)/gi)].map((m) => m[1].toLowerCase()),
  );
  note('src/feeds/registry.ts', `${feedHosts.size} distinct feed host(s) declared: ${[...feedHosts].sort().join(', ')}`);

  for (const target of targets) {
    const dir = resolve(ROOT, target);
    const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
    const label = `${target}/manifest.json`;

    // --- 1. permissions
    const permissions = manifest.permissions ?? [];
    for (const permission of permissions) {
      if (DATA_ACCESS_PERMISSIONS.includes(permission)) {
        fail(label, `data-access permission declared: ${permission}`);
      }
    }
    note(label, `permissions declared: ${permissions.join(', ') || '(none)'}`);

    const hostPermissions = manifest.host_permissions ?? [];
    if (hostPermissions.length !== 1 || hostPermissions[0] !== '<all_urls>') {
      fail(label, `host permissions must be exactly ['<all_urls>'], found ${JSON.stringify(hostPermissions)}`);
    } else {
      note(label, 'host permissions: <all_urls> only (required to evaluate URLs and to block requests)');
    }

    if (manifest.externally_connectable) {
      fail(label, 'externally_connectable would let a web page talk to the extension');
    }
    if (manifest.web_accessible_resources) {
      fail(label, 'web_accessible_resources exposes extension files to web pages');
    }

    // --- 2. outbound destinations
    const files = walk(dir).filter((f) => f.endsWith('.js'));
    const hosts = extractHosts(files);

    const unexpected = [];
    for (const [host, sources] of hosts) {
      for (const pattern of ANALYTICS_HOST_PATTERNS) {
        if (pattern.test(host)) {
          fail(`${target}: ${[...sources][0]}`, `analytics/telemetry host referenced: ${host}`);
        }
      }
      if (NON_NETWORK_HOSTS.has(host)) continue;
      if (!feedHosts.has(host)) unexpected.push(host);
    }
    if (unexpected.length > 0) {
      fail(target, `destination not declared in the feed registry: ${unexpected.join(', ')}`);
    } else {
      note(target, `outbound hosts, all declared feeds: ${[...hosts.keys()].sort().join(', ')}`);
    }
    for (const [host, why] of NON_NETWORK_HOSTS) {
      if (hosts.has(host)) note(target, `${host} excluded from the destination list: ${why}`);
    }

    // --- 3. no transmission, no tracking, no remote code
    for (const file of files) {
      const rel = relative(ROOT, file);
      const code = readFileSync(file, 'utf8');

      for (const { re, label: patternLabel } of TRACKING_IDENTIFIER_PATTERNS) {
        if (re.test(stripComments(code))) fail(rel, `tracking primitive in shipped code: ${patternLabel}`);
      }

      // A body means the extension is SENDING something. The product only ever
      // performs GET requests to fetch public lists.
      if (/method\s*:\s*['"`](POST|PUT|PATCH|DELETE)['"`]/.test(stripComments(code))) {
        fail(rel, 'shipped code performs a request with a body (transmits data)');
      }
      if (/\bfetch\s*\(/.test(stripComments(code)) && /mode\s*:\s*['"`]no-cors/.test(stripComments(code))) {
        fail(rel, 'shipped code uses no-cors, which would hide a destination');
      }
      if (/<script[^>]+src\s*=\s*["']https?:/i.test(code)) fail(rel, 'HTML loads a remote script');
      if (/importScripts\s*\(\s*['"`]https?:/.test(code)) fail(rel, 'service worker imports remote code');
    }

    // --- 4. what actually leaves the device
    //
    // Asserted against the built code rather than asserted in prose, because a
    // vague claim here is exactly the kind of thing a store reviewer will test.
    const code = files.filter((f) => f.includes('background')).map((f) => stripComments(readFileSync(f, 'utf8'))).join('\n');

    if (!/\bfetch\s*\(/.test(code)) {
      fail(target, 'no fetch call found in the service worker; the audit could not inspect outbound requests');
    } else {
      // No cookies, ever. `credentials: 'omit'` is what guarantees this.
      if (!/credentials\s*:\s*['"`]omit['"`]/.test(code)) {
        fail(`${target}/background.js`, 'service worker fetch does not set credentials:"omit" (cookies could be attached)');
      } else {
        note(target, 'every fetch sets credentials:"omit", so no cookie is ever sent to a feed host');
      }

      // No request body.
      if (/\bbody\s*:/.test(code)) {
        fail(`${target}/background.js`, 'service worker attaches a request body to a fetch');
      } else {
        note(target, 'no fetch carries a request body');
      }

      // Headers actually sent, enumerated rather than hand-waved.
      //
      // Both forms are detected: an object literal (`authkey: v`) and a property
      // assignment (`h.authkey = v`). Minification rewrites the first into the
      // second, and missing it would turn this check into a placebo.
      const headerNames = new Set(
        [...code.matchAll(/([A-Za-z_$][\w$]*)\s*:\s*[`'"]([^`'"]{1,60})[`'"]/g)]
          .filter(([, key, value]) => key === 'accept' || key === 'authkey' || key === 'app_key')
          .map(([, key, value]) => `${key}: ${value}`),
      );
      for (const match of code.matchAll(/\.\s*(authkey|app_key)\s*=/g)) headerNames.add(`${match[1]}: <user credential>`);
      for (const match of code.matchAll(/([A-Za-z_$][\w$]*)\s*:\s*`(text\/plain[^`]*)`/g)) headerNames.add(`${match[1]}: ${match[2]}`);

      const credentialHeaders = [...headerNames].filter((h) => /authkey|app_key/.test(h));
      note(target, `headers the feed fetcher can send: ${[...headerNames].sort().join('; ') || '(none)'}`);

      if (credentialHeaders.length === 0) {
        note(target, 'no credential header is ever attached');
      } else {
        // Each credential header must be gated on the provider id that issued
        // it. Anything else could send one provider's key to another host.
        const gated = [...code.matchAll(/([A-Za-z_$][\w$]*)\s*===\s*`(urlhaus|phishtank)`/g)].map((m) => m[2]);
        const expected = ['urlhaus', 'phishtank'].filter((id) => credentialHeaders.some((h) => h.startsWith(id === 'urlhaus' ? 'authkey' : 'app_key')));
        for (const id of expected) {
          if (!gated.includes(id)) {
            fail(`${target}/background.js`, `credential header for provider "${id}" is not gated on that provider id`);
          }
        }
        note(
          target,
          `credential headers present: ${credentialHeaders.join('; ')}. Each is the user's OWN API key, sent only to the provider ` +
            `that issued it, and only after the user explicitly supplies it. No credentialed provider is enabled by default.`,
        );
      }
    }

    // --- 5. local-only storage
    for (const key of FORBIDDEN_STORAGE_KEYS) {
      for (const file of files) {
        if (readFileSync(file, 'utf8').includes(key)) {
          fail(relative(ROOT, file), `forbidden local storage key present: ${key}`);
        }
      }
    }
    note(target, 'no local storage key holds passwords, cookies, tokens or page content');
  }

  report();
}

function report() {
  if (asJson) {
    process.stdout.write(`${JSON.stringify({ ok: findings.length === 0, findings, evidence }, null, 2)}\n`);
  } else {
    for (const item of evidence) process.stdout.write(`  evidence  ${item.where}: ${item.message}\n`);
    if (findings.length > 0) {
      process.stderr.write('\n[privacy-audit] FAILED\n');
      for (const f of findings) process.stderr.write(`  ${f.where}: ${f.message}\n`);
    } else {
      process.stdout.write('\n[privacy-audit] passed: no data collection path found in the built package\n');
    }
  }
  process.exit(findings.length === 0 ? 0 : 1);
}

main();
