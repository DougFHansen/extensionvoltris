/**
 * Download risk analysis.
 *
 * Capability statement (Section 6 of the specification):
 *  - We CAN observe: the download's final filename, its originating page/referrer
 *    and its URL, through `chrome.downloads`.
 *  - We CAN cancel a download through `chrome.downloads.cancel()`.
 *  - We CANNOT scan file contents. There is no extension API for that and we do
 *    not attempt it.
 *  - We DO NOT replace or disable Chrome's own download checks, SmartScreen or
 *    Defender, and we never block a download merely for having a .exe/.msi/.zip
 *    extension.
 *
 * Policy: alerts are the default. Cancellation only happens when the user opted
 * into the `cancel` action AND the evidence is high-confidence (a double
 * extension combined with another signal, or a known-malicious source).
 */
import type { Confidence, DownloadAnalysis, DownloadRiskVerdict, RiskReason } from '../core/types';
import { parseTarget } from './url-normalize';
import { resolvePublicSuffix } from './psl';
import { analyzeUrl } from './risk';
import type { AnalyzeOptions } from './risk';
import { lookupThreat } from './reputation';

/** Extensions that legitimately execute or install code. Informational only. */
const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'msi', 'msix', 'msixbundle', 'appx', 'appxbundle', 'bat', 'cmd',
  'com', 'scr', 'pif', 'vbs', 'vbe', 'js', 'jse', 'ws', 'wsh', 'ps1', 'psm1',
  'jar', 'reg', 'lnk', 'hta', 'cpl', 'dll', 'sys', 'drv', 'gadget', 'msc',
  'apk', 'xapk', 'dmg', 'pkg', 'deb', 'rpm', 'run', 'sh', 'bash',
]);

/** Extensions that are never executable and are the classic disguise target. */
const DOCUMENT_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv',
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'mp3', 'mp4', 'avi', 'mkv',
  'zip', 'rar', '7z', 'tar', 'gz', 'odt', 'ods', 'odp',
]);

/** Archive types used to smuggle a payload past a naive extension check. */
const ARCHIVE_EXTENSIONS = new Set(['zip', 'rar', '7z', 'tar', 'gz', 'iso', 'cab']);

export interface DownloadFacts {
  readonly filename: string;
  /** Page the download was started from, when the API exposes it. */
  readonly referrer?: string;
  /** Absolute URL the file came from, when available. */
  readonly url?: string;
}

/**
 * Extracts the effective extension, taking double extensions into account.
 * `invoice.pdf.exe` -> `exe` (the one that actually executes).
 */
export function effectiveExtension(filename: string): { extension: string; segments: string[]; doubleExtension: boolean } {
  const base = filename.split(/[\\/]/).pop() ?? filename;
  const parts = base.split('.');
  const segments = parts.slice(1).map((p) => p.toLowerCase()).filter((p) => p.length > 0 && p.length <= 12);
  if (segments.length === 0) return { extension: '', segments, doubleExtension: false };
  const extension = segments[segments.length - 1]!;
  const doubleExtension = segments.length >= 2 && EXECUTABLE_EXTENSIONS.has(extension) && DOCUMENT_EXTENSIONS.has(segments[segments.length - 2]!);
  return { extension, segments, doubleExtension };
}

/**
 * Windows reserved device names. `CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9`.
 * A file named `CON.js` cannot be written on Windows but can confuse tooling.
 */
const RESERVED_DEVICE_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i;

export interface AnalyzeDownloadsOptions extends AnalyzeOptions {
  readonly warnDangerousExtensions: boolean;
  readonly warnDoubleExtensions: boolean;
  readonly downloadAction: 'alert' | 'cancel';
}

export async function analyzeDownload(
  facts: DownloadFacts,
  opts: AnalyzeDownloadsOptions,
): Promise<DownloadAnalysis> {
  const reasons: RiskReason[] = [];
  const filename = facts.filename ?? '';
  const { extension, doubleExtension } = effectiveExtension(filename);

  const sourceTarget = parseTarget(facts.url ?? facts.referrer ?? '', resolvePublicSuffix);
  // Only a real registrable domain (or an IP literal) is reported. A bare label
  // such as "localhost" or a mangled string tells the user nothing and would
  // only add noise to the UI.
  const sourceDomain = sourceTarget.registrableDomain ?? (sourceTarget.isIpLiteral ? sourceTarget.hostname : null);

  // ---- Source reputation ---------------------------------------------------
  let sourceVerdict: DownloadAnalysis['sourceVerdict'] = null;
  const threat = await lookupThreat(sourceTarget.hostname, sourceTarget.registrableDomain);
  if (threat && threat.record.category !== 'tracker' && threat.record.category !== 'ad') {
    sourceVerdict = 'known-malicious';
    reasons.push({
      code: 'downloads.from_known_malicious',
      weight: 90,
      confidence: 'high',
      severity: 'critical',
      data: { provider: threat.record.providerId, matched: threat.matchedDomain },
    });
  }

  // ---- Double extension ----------------------------------------------------
  // No legitimate file is named `invoice.pdf.exe`. This is a deliberate
  // deception technique, so it carries critical severity even though the
  // default action is only a warning.
  if (doubleExtension && opts.warnDoubleExtensions) {
    reasons.push({
      code: 'downloads.double_extension',
      weight: 65,
      confidence: 'high',
      severity: 'critical',
      data: { extension },
    });
  }

  // ---- Dangerous extension -------------------------------------------------
  // Informational on its own: legitimate installers exist. It only becomes
  // evidence when combined with something else.
  if (extension.length > 0 && EXECUTABLE_EXTENSIONS.has(extension) && opts.warnDangerousExtensions) {
    reasons.push({
      code: 'downloads.dangerous_extension',
      weight: doubleExtension ? 0 : 18,
      confidence: doubleExtension ? 'low' : 'medium',
      severity: doubleExtension ? 'low' : 'medium',
      data: { extension, archive: ARCHIVE_EXTENSIONS.has(extension) ? 1 : 0 },
    });
  }

  if (RESERVED_DEVICE_RE.test(filename)) {
    reasons.push({ code: 'downloads.dangerous_extension', weight: 10, confidence: 'low', severity: 'low', data: { extension } });
  }

  // ---- Cross-check the page context ---------------------------------------
  let pageVerdict: DownloadAnalysis['sourceVerdict'] = null;
  if (facts.referrer && facts.referrer !== facts.url) {
    const ref = parseTarget(facts.referrer, resolvePublicSuffix);
    if (ref.hostname) {
      const refAnalysis = await analyzeUrl(facts.referrer, opts);
      pageVerdict = refAnalysis.verdict;
      if (refAnalysis.verdict === 'known-malicious') {
        reasons.push({ code: 'downloads.from_known_malicious', weight: 70, confidence: 'high', severity: 'high', data: { matched: ref.hostname } });
      }
    }
  }

  const verdict = decideVerdict(reasons);
  const confidence: Confidence =
    reasons.some((r) => r.confidence === 'high') ? 'high' : reasons.some((r) => r.weight > 0) ? 'medium' : 'low';

  // Cancellation is only offered when the user opted in AND we have at least one
  // high-confidence, non-informational reason.
  const cancellable = opts.downloadAction === 'cancel' && reasons.some((r) => r.severity === 'critical' || r.severity === 'high');

  return {
    verdict,
    confidence,
    filename,
    extension,
    reasons,
    sourceDomain,
    sourceVerdict: sourceVerdict ?? pageVerdict,
    cancellable,
  };
}

function decideVerdict(reasons: readonly RiskReason[]): DownloadRiskVerdict {
  if (reasons.length === 0) return 'safe';
  const hasCritical = reasons.some((r) => r.severity === 'critical' && r.confidence === 'high');
  const hasHigh = reasons.some((r) => r.severity === 'high' && r.confidence === 'high');
  if (hasCritical) return 'dangerous';
  if (hasHigh) return 'caution';
  const weight = reasons.reduce((sum, r) => sum + r.weight, 0);
  return weight >= 40 ? 'caution' : 'safe';
}
