/**
 * Page-level scam signal validation and scoring.
 *
 * The content script runs in an isolated world and reports STRUCTURE ONLY.
 * It never reads input values, cookies, storage or tokens. Everything that
 * arrives here is treated as hostile page data and re-validated.
 *
 * Because Manifest V3 offers no way to prove a page is lying (no access to
 * certificate history, no brand-verification service, no redirect-chain
 * introspection for server-side hops), the conclusions we can reach here are
 * deliberately narrow: "this page has the shape of a fake browser update". They
 * are presented as warnings with the evidence, never as proof.
 */
import type { Confidence, PageSignals, RiskReason, ScamSignal } from '../core/types';

const MAX_EVIDENCE_ITEMS = 8;
const MAX_EVIDENCE_LENGTH = 120;

const SIGNAL_CODES = new Set<ScamSignal['code']>([
  'scam.fake_browser_update',
  'scam.fake_virus_alert',
  'scam.software_install_prompt',
  'scam.credential_form',
  'scam.lookalike_link_domain',
]);

function isConfidence(value: unknown): value is Confidence {
  return value === 'high' || value === 'medium' || value === 'low';
}

/** Validates a raw content-script payload. Returns null when untrustworthy. */
export function sanitizeSignals(raw: unknown): { url: string; signals: ScamSignal[]; formsAnalyzed: number; linksAnalyzed: number } | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const record = raw as Record<string, unknown>;
  const url = typeof record.url === 'string' ? record.url : '';
  if (url.length === 0 || url.length > 4096) return null;

  const rawSignals = Array.isArray(record.signals) ? record.signals : [];
  const signals: ScamSignal[] = [];

  for (const item of rawSignals) {
    if (typeof item !== 'object' || item === null) continue;
    const s = item as Record<string, unknown>;
    if (typeof s.code !== 'string' || !SIGNAL_CODES.has(s.code as ScamSignal['code'])) continue;
    const evidence = Array.isArray(s.evidence)
      ? s.evidence
          .filter((e): e is string => typeof e === 'string')
          .slice(0, MAX_EVIDENCE_ITEMS)
          // Evidence is displayed with textContent, but we still bound it so a
          // page cannot force megabyte-long strings into our UI.
          .map((e) => e.slice(0, MAX_EVIDENCE_LENGTH))
      : [];
    signals.push({
      code: s.code as ScamSignal['code'],
      confidence: isConfidence(s.confidence) ? s.confidence : 'low',
      evidence,
    });
    if (signals.length >= 8) break;
  }

  const formsAnalyzed = typeof record.formsAnalyzed === 'number' && Number.isFinite(record.formsAnalyzed)
    ? Math.min(1000, Math.max(0, Math.round(record.formsAnalyzed)))
    : 0;
  const linksAnalyzed = typeof record.linksAnalyzed === 'number' && Number.isFinite(record.linksAnalyzed)
    ? Math.min(10_000, Math.max(0, Math.round(record.linksAnalyzed)))
    : 0;

  return { url, signals, formsAnalyzed, linksAnalyzed };
}

const REASON_BY_CODE: Record<ScamSignal['code'], { code: RiskReason['code']; weight: number; severity: RiskReason['severity'] }> = {
  'scam.fake_browser_update': { code: 'scam.browser_update_claim', weight: 40, severity: 'medium' },
  'scam.fake_virus_alert': { code: 'scam.fake_virus_alert', weight: 45, severity: 'medium' },
  'scam.software_install_prompt': { code: 'scam.software_install_prompt', weight: 28, severity: 'medium' },
  'scam.credential_form': { code: 'scam.credential_form', weight: 18, severity: 'low' },
  'scam.lookalike_link_domain': { code: 'credential_brand_on_lookalike', weight: 35, severity: 'medium' },
};

export function analyzePageSignals(
  raw: unknown,
  _sender: chrome.runtime.MessageSender,
): PageSignals {
  const sanitized = sanitizeSignals(raw);
  const analyzedAt = Date.now();

  if (sanitized === null) {
    return { url: '', hostname: null, signals: [], formsAnalyzed: 0, linksAnalyzed: 0, analyzedAt };
  }

  let hostname: string | null = null;
  try {
    hostname = new URL(sanitized.url).hostname;
  } catch {
    hostname = null;
  }

  return {
    url: sanitized.url,
    hostname,
    signals: sanitized.signals,
    formsAnalyzed: sanitized.formsAnalyzed,
    linksAnalyzed: sanitized.linksAnalyzed,
    analyzedAt,
  };
}

/** Converts page signals into risk reasons with explicit weights. */
export function signalsToReasons(signals: readonly ScamSignal[]): RiskReason[] {
  const out: RiskReason[] = [];
  for (const signal of signals) {
    const mapping = REASON_BY_CODE[signal.code];
    if (!mapping) continue;
    const factor = signal.confidence === 'high' ? 1 : signal.confidence === 'medium' ? 0.6 : 0.3;
    out.push({
      code: mapping.code,
      weight: Math.round(mapping.weight * factor),
      confidence: signal.confidence,
      severity: mapping.severity,
      data: { evidence: signal.evidence.slice(0, 3).join(' | ') },
    });
  }
  return out;
}
