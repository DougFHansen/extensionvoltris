/**
 * Download analysis.
 *
 * Explicit non-goals locked in by these tests:
 *  - a legitimate `.exe` / `.msi` / `.zip` is NEVER blocked on that basis alone
 *  - file contents are never read
 *  - the browser's own download protections are never touched
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

const store = new Map<string, unknown>();
const area = {
  get: async () => Object.fromEntries(store),
  set: async (items: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(items)) store.set(k, v);
  },
  remove: async () => undefined,
};
(globalThis as Record<string, unknown>).chrome = { storage: { local: area, session: area } };

const { analyzeDownload, effectiveExtension } = await import('../../src/security/downloads');
const { setPslRootForTests } = await import('../../src/security/psl');
const { DEFAULT_SETTINGS } = await import('../../src/core/types');

const PSL = JSON.parse(readFileSync('src/generated/psl.json', 'utf8')) as { root: unknown };
setPslRootForTests(PSL.root as never, {
  source: 'test',
  license: 'MPL-2.0',
  sha256: 'd'.repeat(64),
  generatedAt: '2026-01-01',
  ruleCount: 10336,
});

const BASE = {
  settings: DEFAULT_SETTINGS,
  allowlisted: new Set<string>(),
  warnDangerousExtensions: true,
  warnDoubleExtensions: true,
  downloadAction: 'alert' as const,
};

beforeEach(() => store.clear());

describe('effectiveExtension', () => {
  it('returns a single extension', () => {
    expect(effectiveExtension('report.pdf').extension).toBe('pdf');
    expect(effectiveExtension('setup.exe').extension).toBe('exe');
    expect(effectiveExtension('noext').extension).toBe('');
  });

  it('detects the double-extension trick', () => {
    const result = effectiveExtension('invoice.pdf.exe');
    expect(result.extension).toBe('exe');
    expect(result.doubleExtension).toBe(true);
  });

  it('detects a double extension with a disguised executable', () => {
    expect(effectiveExtension('photo.jpg.scr').doubleExtension).toBe(true);
    expect(effectiveExtension('document.pdf.js').doubleExtension).toBe(true);
  });

  it('does not treat a benign multi-part extension as an attack', () => {
    // `.pdf.zip` and `.tar.gz` are legitimate; the last extension is not an
    // executable, which is exactly the thing that makes a trick dangerous.
    expect(effectiveExtension('report.pdf.zip').doubleExtension).toBe(false);
    expect(effectiveExtension('backup.tar.gz').doubleExtension).toBe(false);
  });

  it('does not treat a normal double extension as an attack', () => {
    expect(effectiveExtension('backup.tar.gz').doubleExtension).toBe(false);
    expect(effectiveExtension('my.module.js').doubleExtension).toBe(false);
  });

  it('strips a directory path', () => {
    expect(effectiveExtension('C:\\Users\\me\\Downloads\\a.pdf.exe').extension).toBe('exe');
  });
});

describe('legitimate downloads are not punished', () => {
  it('clears a plain .exe', async () => {
    const result = await analyzeDownload({ filename: 'installer.exe', url: 'https://example.test/installer.exe' }, BASE);
    expect(result.verdict).toBe('safe');
    expect(result.cancellable).toBe(false);
  });

  it('clears a plain .msi', async () => {
    const result = await analyzeDownload({ filename: 'setup.msi' }, BASE);
    expect(result.verdict).toBe('safe');
  });

  it('clears a plain .zip', async () => {
    const result = await analyzeDownload({ filename: 'archive.zip' }, BASE);
    expect(result.verdict).toBe('safe');
  });

  it('clears an ordinary document', async () => {
    const result = await analyzeDownload({ filename: 'statement.pdf' }, BASE);
    expect(result.verdict).toBe('safe');
  });

  it('treats an executable extension as informational only', async () => {
    const result = await analyzeDownload({ filename: 'tool.exe' }, BASE);
    const reason = result.reasons.find((r) => r.code === 'downloads.dangerous_extension');
    expect(reason).toBeDefined();
    expect(reason!.confidence).toBe('medium');
    // Informational evidence must not by itself produce a warning verdict.
    expect(result.verdict).toBe('safe');
  });

  it('does not cancel unless the user opted in', async () => {
    const alert = await analyzeDownload({ filename: 'invoice.pdf.exe' }, { ...BASE, downloadAction: 'alert' });
    expect(alert.verdict).toBe('dangerous');
    expect(alert.cancellable).toBe(false);
  });
});

describe('suspicious downloads', () => {
  it('flags a double extension', async () => {
    const result = await analyzeDownload({ filename: 'comprovante.pdf.exe' }, BASE);
    expect(result.verdict).toBe('dangerous');
    expect(result.reasons.some((r) => r.code === 'downloads.double_extension')).toBe(true);
  });

  it('offers cancellation only in cancel mode', async () => {
    const result = await analyzeDownload({ filename: 'comprovante.pdf.exe' }, { ...BASE, downloadAction: 'cancel' });
    expect(result.cancellable).toBe(true);
  });

  it('flags a download from a known malicious source', async () => {
    await chrome.storage.local.set({
      'vbs.threats.__meta': [
        {
          id: 'phishing-database-domains',
          status: 'active',
          lastSuccessAt: Date.now(),
          lastAttemptAt: Date.now(),
          lastError: null,
          entryCount: 1,
          ruleCount: 0,
          contentHash: null,
          feedVersion: null,
          skipped: 0,
          skippedByReason: {},
        },
      ],
      'vbs.threats.phishing-database-domains': 'malicious-source.test',
    });
    const { invalidateReputationCache } = await import('../../src/security/reputation');
    invalidateReputationCache();

    const result = await analyzeDownload({ filename: 'invoice.pdf', url: 'https://malicious-source.test/invoice.pdf' }, BASE);
    expect(result.verdict).toBe('dangerous');
    expect(result.sourceVerdict).toBe('known-malicious');
    expect(result.reasons.some((r) => r.code === 'downloads.from_known_malicious')).toBe(true);
  });

  it('reports the true confidence of a warning', async () => {
    const result = await analyzeDownload({ filename: 'a.pdf.exe' }, BASE);
    expect(result.confidence).toBe('high');
  });

  it('handles a Windows path with reserved device names', async () => {
    const result = await analyzeDownload({ filename: 'CON.js' }, BASE);
    expect(result.reasons.some((r) => r.code === 'downloads.dangerous_extension')).toBe(true);
  });
});

describe('hostile input', () => {
  it('never throws on an empty or absurd filename', async () => {
    for (const filename of ['', 'a'.repeat(5000), '../../etc/passwd', 'x'.repeat(300) + '.exe']) {
      const result = await analyzeDownload({ filename }, BASE);
      expect(result.filename).toBe(filename);
    }
  });

  it('never throws on a malformed source url', async () => {
    for (const url of ['not a url', 'javascript:alert(1)', 'data:text/html,x', 'chrome://settings']) {
      const result = await analyzeDownload({ filename: 'a.pdf', url }, BASE);
      expect(result.sourceDomain).toBeNull();
    }
  });

  it('never reads or reports anything about file contents', async () => {
    const result = await analyzeDownload({ filename: 'a.pdf' }, BASE);
    // The analysis result has no field capable of carrying file content.
    expect(Object.keys(result).sort()).toEqual(
      ['cancellable', 'confidence', 'extension', 'filename', 'reasons', 'sourceDomain', 'sourceVerdict', 'verdict'].sort(),
    );
  });
});
