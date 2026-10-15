/**
 * PRIVACY LINT - enforces the specification's hard privacy promises as an
 * automated test rather than as a promise in documentation.
 *
 * These checks run over the real source files on every `npm test`, so a future
 * change that starts reading a password field fails the build.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

function collect(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) collect(full, out);
    else if (full.endsWith('.ts') || full.endsWith('.html')) out.push(full);
  }
  return out;
}

const SOURCE_FILES = collect('src').map((f) => ({ path: f, code: readFileSync(f, 'utf8') }));
const CONTENT_FILES = SOURCE_FILES.filter((f) => f.path.startsWith('src\\content') || f.path.includes('scam-scan-source') || f.path.includes('scam') || f.path.includes('content-bridge'));

/** Strips comments so documentation cannot mask a real violation. */
function stripComments(code: string): string {
  return code.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/**
 * Finds files whose EXECUTABLE code matches `pattern`.
 *
 * Comments are stripped first: several modules document at length why we do not
 * use `onRuleMatchedDebug`, and that reasoning must not be mistaken for a call.
 */
function grepFiles(dir: string, pattern: RegExp): string[] {
  return SOURCE_FILES.filter((f) => pattern.test(stripComments(f.code))).map((f) => relative('.', f.path)).sort();
}

describe('content script privacy contract', () => {
  it('has content scripts to check', () => {
    expect(CONTENT_FILES.length).toBeGreaterThan(0);
  });

  it.each([
    ['reading a password input value', /\.value\b/],
    ['reading a textarea value', /textarea[^\n]*\.value/],
    ['reading document.cookie', /document\s*\.\s*cookie/],
    ['reading localStorage', /localStorage/],
    ['reading sessionStorage', /sessionStorage/],
    ['reading indexedDB', /indexedDB/],
    ['reading a clipboard', /clipboard/i],
    ['reading autofill or payment fields by value', /cc-number|cardnumber|ccnumber/],
  ])('never %s', (_label, pattern) => {
    const offenders = CONTENT_FILES.filter((f) => pattern.test(stripComments(f.code))).map((f) => relative('.', f.path));
    expect(offenders).toEqual([]);
  });

  it('never installs a permanent MutationObserver', () => {
    const offenders = CONTENT_FILES.filter((f) => /new\s+MutationObserver/.test(stripComments(f.code))).map((f) => relative('.', f.path));
    expect(offenders).toEqual([]);
  });

  it('never installs a permanent polling timer', () => {
    const offenders = CONTENT_FILES.filter((f) => /setInterval\s*\(/.test(stripComments(f.code))).map((f) => relative('.', f.path));
    expect(offenders).toEqual([]);
  });

  it('bounds its DOM walk', () => {
    const offenders = CONTENT_FILES.filter((f) => {
      const code = stripComments(f.code);
      return /document\.querySelectorAll\s*\(/.test(code) && !/Math\.min|MAX_/.test(code);
    }).map((f) => relative('.', f.path));
    expect(offenders).toEqual([]);
  });
});

describe('extension-wide security contract', () => {
  it('never uses eval or the Function constructor', () => {
    const offenders = SOURCE_FILES.filter((f) => /\beval\s*\(|new\s+Function\s*\(/.test(stripComments(f.code))).map((f) => f.path);
    expect(offenders).toEqual([]);
  });

  it('never uses innerHTML, outerHTML, insertAdjacentHTML or document.write', () => {
    const offenders = SOURCE_FILES.filter((f) => /\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write/.test(stripComments(f.code))).map(
      (f) => f.path,
    );
    expect(offenders).toEqual([]);
  });

  it('renders every user-facing string through textContent', () => {
    // The component layer is the only sanctioned way to create DOM nodes.
    const uiFiles = SOURCE_FILES.filter((f) => f.path.startsWith('src\\ui'));
    const offenders = uiFiles.filter((f) => !/textContent/.test(f.code) && /document\.createElement/.test(f.code)).map((f) => f.path);
    expect(offenders).toEqual([]);
  });

  it('declares no externally_connectable surface', () => {
    const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as Record<string, unknown>;
    expect(manifest.externally_connectable).toBeUndefined();
  });

  it('requests only permissions that are justified by a shipped feature', () => {
    const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as {
      permissions: string[];
      host_permissions: string[];
    };
    const allowed = new Set([
      'storage',
      'alarms',
      'declarativeNetRequest',
      // Observes a failed top-level navigation so the block can be counted and
      // explained. Available to published extensions, no install-time warning,
      // and we never persist or transmit the events.
      'webNavigation',
      'downloads',
      'notifications',
      'scripting',
      'activeTab',
    ]);
    for (const permission of manifest.permissions) {
      expect(allowed.has(permission), `undeclared permission: ${permission}`).toBe(true);
    }
    // `<all_urls>` is the only host permission, and it is required to evaluate
    // URLs and to block requests.
    expect(manifest.host_permissions).toEqual(['<all_urls>']);
  });

  it('ships no permission that only exists in development builds', () => {
    // `declarativeNetRequestFeedback` gates `onRuleMatchedDebug` and
    // `getMatchedRules`, which Chrome documents as unpacked-only. Requesting it
    // would ship a permission that buys nothing in a store install while
    // inviting a reviewer to ask what it is for.
    const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as { permissions: string[] };
    expect(manifest.permissions).not.toContain('declarativeNetRequestFeedback');
    expect(manifest.permissions).not.toContain('declarativeNetRequestWithHostAccess');
  });

  it('never references the unpacked-only matched-rule feed in shipped code', () => {
    // Guards against the regression that made every block counter read zero
    // after a store install: statistics and the explanatory block page were both
    // driven by `onRuleMatchedDebug`.
    const offenders = grepFiles('src', /onRuleMatchedDebug|getMatchedRules|declarativeNetRequestFeedback/);
    expect(offenders).toEqual([]);
  });

  it('never requests high-risk permissions', () => {
    const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as { permissions: string[] };
    const forbidden = [
      'cookies', 'history', 'webRequest', 'webRequestBlocking', 'management',
      'nativeMessaging', 'privacy', 'identity', 'proxy', 'debugger',
      'desktopCapture', 'clipboardWrite', 'browsingData',
    ];
    for (const permission of manifest.permissions) {
      expect(forbidden, `forbidden permission: ${permission}`).not.toContain(permission);
    }
  });

  it('ships a restrictive content security policy', () => {
    const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as {
      content_security_policy: { extension_pages: string };
    };
    const csp = manifest.content_security_policy.extension_pages;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).toContain("object-src 'none'");
  });

  it('performs no direct network I/O outside the feed updater', () => {
    // `fetch(chrome.runtime.getURL(...))` reads a file bundled WITH the
    // extension; it is not a network call and is explicitly allowed.
    const remoteCallers = SOURCE_FILES.filter((f) => {
      const code = stripComments(f.code);
      if (!/\bfetch\s*\(/.test(code)) return false;
      const calls = [...code.matchAll(/\bfetch\s*\(([^)]*)\)/g)].map((m) => m[1]!.trim());
      return calls.some((arg) => !/^chrome\.runtime\.getURL\(/.test(arg));
    }).map((f) => relative('.', f.path));

    // The updater reaches the network through an INJECTABLE alias (`doFetch`),
    // which is what makes the update cycle testable without a network. No other
    // module may fetch anything at all.
    expect(remoteCallers).toEqual([]);
    expect(readFileSync('src/feeds/updater.ts', 'utf8')).toContain('options.fetchImpl ?? fetch');
  });

  it('ships no telemetry call site', () => {
    // Brand reference data legitimately names analytics domains as things we
    // BLOCK, so only a file that can actually send data is flagged.
    const TELEMETRY = /google-analytics|googletagmanager|segment\.io|mixpanel|sentry\.io|amplitude|posthog|hotjar|fullstory/i;
    const offenders = SOURCE_FILES.filter((f) => {
      const code = stripComments(f.code);
      if (!TELEMETRY.test(code)) return false;
      return /\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket\s*\(|navigator\.sendBeacon/.test(code);
    }).map((f) => f.path);
    expect(offenders).toEqual([]);
  });
});

describe('service worker performance contract', () => {
  it('never installs a continuous polling loop', () => {
    const background = SOURCE_FILES.filter((f) => f.path.startsWith('src\\background'));
    const offenders = background.filter((f) => /setInterval\s*\(/.test(stripComments(f.code))).map((f) => f.path);
    expect(offenders).toEqual([]);
  });

  it('registers every listener at module scope', () => {
    const sw = readFileSync('src/background/service-worker.ts', 'utf8');
    expect(sw).toMatch(/installListeners\(\)/);
  });
});
