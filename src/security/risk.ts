/**
 * Multi-layer phishing / scam risk engine.
 *
 * This module is the ONLY place where evidence is turned into a verdict.
 *
 * Hard rules enforced here (Section 2 of the specification):
 *  - `known-malicious` requires evidence from a verified feed. A high heuristic
 *    score NEVER produces it.
 *  - Absence of HTTPS, subdomain depth and the word "login" are NOT signals.
 *  - Every reason carries a code, a weight, a confidence and a severity so the
 *    UI can explain itself without inventing claims.
 *  - When coverage is insufficient the result is `not-analyzed`, never
 *    `no-threat-found`.
 */
import type {
  AnalysisResult,
  Confidence,
  RiskReason,
  RiskVerdict,
  ThreatCategory,
  ThreatSourceInfo,
} from '../core/types';
import { labelsOf, parseTarget, type ParsedTarget } from './url-normalize';
import { resolvePublicSuffix, pslStatus } from './psl';
import { analyzeUnicode } from './unicode';
import { analyzeUrlShape, detectImpersonation } from './heuristics';
import { lookupThreat } from './reputation';
import { isShortener, shortenerEntry } from './shortener';
import { PROVIDER_INDEX } from '../feeds/registry';

/** Weights are additive but saturating; the score is capped at 100. */
const SCORE_CAP = 100;

/** A score at or above this level still yields only `suspicious`. */
const SUSPICIOUS_THRESHOLD = 45;

export interface AnalyzeOptions {
  readonly settings: {
    readonly protectionEnabled: boolean;
    readonly phishingEngineEnabled: boolean;
    readonly blockPhishing: boolean;
    readonly blockMalware: boolean;
    readonly blockScam: boolean;
    readonly blockMalwareDistribution: boolean;
  };
  /** Domains the user explicitly allowed. */
  readonly allowlisted: ReadonlySet<string>;
  /** Extra context, e.g. a redirect chain observed by webNavigation. */
  readonly redirectTargets?: readonly string[];
}

const CATEGORY_REASON: Record<ThreatCategory, RiskReason['code']> = {
  phishing: 'feed.known_phishing',
  malware: 'feed.known_malicious',
  malware_distribution: 'feed.known_malware_distribution',
  scam: 'feed.known_scam',
  tracker: 'feed.known_malicious',
  ad: 'feed.known_malicious',
};

/**
 * Verifies that the feed carrying a `known-malicious` verdict is currently
 * usable. A stale or failed feed must not be presented as a live detection.
 */
function feedIsAuthoritative(state: { status: string; lastSuccessAt: number | null } | undefined): boolean {
  if (!state) return false;
  if (state.status === 'active' || state.status === 'bundled_snapshot') return true;
  if (state.status === 'stale' && state.lastSuccessAt !== null) return true;
  return false;
}

function dedupeReasons(reasons: readonly RiskReason[]): RiskReason[] {
  const seen = new Map<string, RiskReason>();
  for (const r of reasons) {
    const key = `${r.code}|${String(r.data?.brand ?? '')}|${String(r.data?.keyword ?? '')}`;
    const prev = seen.get(key);
    if (!prev || prev.weight < r.weight) seen.set(key, r);
  }
  return [...seen.values()].sort((a, b) => b.weight - a.weight);
}

function categoryEnabled(cat: ThreatCategory, opts: AnalyzeOptions): boolean {
  switch (cat) {
    case 'phishing':
      return opts.settings.blockPhishing;
    case 'malware':
      return opts.settings.blockMalware;
    case 'scam':
      return opts.settings.blockScam;
    case 'malware_distribution':
      return opts.settings.blockMalwareDistribution;
    default:
      return true;
  }
}

function confidenceFromScore(score: number): Confidence {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

/** Entry point: analyse an untrusted URL, hostname or bare domain. */
export async function analyzeUrl(input: unknown, opts: AnalyzeOptions): Promise<AnalysisResult> {
  const analyzedAt = Date.now();
  const parsed = parseTarget(input, resolvePublicSuffix);

  if (!parsed.normalized || !parsed.hostname) {
    return notAnalyzed(analyzedAt, ['coverage.no_reputation_data']);
  }

  const categories = new Set<ThreatCategory>();
  const reasons: RiskReason[] = [];
  const sources: ThreatSourceInfo[] = [];
  const modulesActive: string[] = [];

  const hostname = parsed.hostname;
  const registrableDomain = parsed.registrableDomain;

  // ---- Layer 0: user intent -------------------------------------------------
  // DESIGN DECISION: allowlisting changes what we DO (rules are bypassed), never
  // what we KNOW. The verdict stays factual - a site listed in a verified feed is
  // still reported as known-malicious - and `allowlisted` is surfaced next to it
  // so the UI can say "you have allowed this site". Silently downgrading the
  // verdict would be a lie the user could act on.
  const allowlisted = registrableDomain !== null && opts.allowlisted.has(registrableDomain);
  if (allowlisted) {
    reasons.push({ code: 'coverage.allowlisted', weight: 0, confidence: 'high', severity: 'info', data: {} });
  }

  // ---- Layer 1: verified reputation ----------------------------------------
  modulesActive.push('reputation');
  const threat = await lookupThreat(hostname, registrableDomain);
  let knownMalicious = false;

  if (threat) {
    const provider = PROVIDER_INDEX.get(threat.provider.id);
    const providerState = threat.provider;
    if (provider && feedIsAuthoritative(providerState) && categoryEnabled(threat.record.category, opts)) {
      knownMalicious = true;
      categories.add(threat.record.category);
      reasons.push({
        code: CATEGORY_REASON[threat.record.category],
        weight: 100,
        confidence: 'high',
        severity: 'critical',
        data: {
          provider: provider.id,
          providerName: provider.name,
          matched: threat.matchedDomain,
        },
      });
      sources.push({
        providerId: provider.id,
        providerName: provider.name,
        url: provider.homepage,
        license: provider.license.name,
        ...(threat.record.since > 0 ? { observedAt: threat.record.since } : {}),
      });
    }
  }

  // ---- Layer 2: Unicode deception -----------------------------------------
  modulesActive.push('unicode');
  const unicodeHost = extractUnicodeHost(input, hostname);
  const suffixLabels = parsed.publicSuffix ? parsed.publicSuffix.split('.').length : 1;
  const allUnicodeLabels = unicodeHost ? labelsOf(unicodeHost) : [];
  // Analyse the UNICODE labels, not the punycode ones: by this point the URL
  // parser has already transliterated `ｐaypal` into `xn--...`, which would hide
  // exactly the evidence we are looking for.
  const unicodeLabels = allUnicodeLabels.slice(0, Math.max(0, allUnicodeLabels.length - suffixLabels));
  const unicode = analyzeUnicode({
    unicodeHost,
    asciiHost: hostname,
    labels: unicodeLabels.length > 0 ? unicodeLabels : hostname.split('.'),
  });

  if (unicode.findings.length > 0) {
    const bidi = unicode.findings.find((f) => f.kind === 'bidi' || f.kind === 'zero_width');
    if (bidi) {
      reasons.push({ code: 'unicode_bidi_control', weight: 55, confidence: 'high', severity: 'high', data: { label: bidi.label } });
    }
    const mixed = unicode.findings.find((f) => f.kind === 'mixed_script');
    if (mixed) {
      reasons.push({
        code: 'unicode_mixed_script',
        weight: 45,
        confidence: 'high',
        severity: 'medium',
        data: { label: mixed.label, scripts: String(mixed.data.scripts ?? '') },
      });
    }
    const homograph = unicode.findings.find((f) => f.kind === 'homograph');
    if (homograph) {
      reasons.push({
        code: 'punycode_homograph',
        weight: 50,
        confidence: 'high',
        severity: 'high',
        data: { label: homograph.label, skeleton: String(homograph.data.skeleton ?? '') },
      });
    } else if (unicode.findings.some((f) => f.kind === 'confusable')) {
      reasons.push({ code: 'unicode_confusable', weight: 26, confidence: 'medium', severity: 'medium', data: {} });
    } else if (unicode.findings.some((f) => f.kind === 'punycode')) {
      // Punycode alone is NOT suspicious - IDN domains are legitimate.
      reasons.push({ code: 'unicode_confusable', weight: 0, confidence: 'low', severity: 'info', data: {} });
    }
  }

  // ---- Layer 3: brand impersonation ----------------------------------------
  // NOTE: impersonation deliberately does NOT add a threat category. Categories
  // drive blocking decisions and only verified feeds may populate them. Here we
  // only accumulate score/reasons, which can at most reach `suspicious`.
  modulesActive.push('impersonation');
  const impersonation = detectImpersonation(hostname, registrableDomain);
  reasons.push(...impersonation.reasons);

  // ---- Layer 4: URL structure ----------------------------------------------
  modulesActive.push('structure');
  const shape = analyzeUrlShape(parsed);
  reasons.push(...shape.reasons);

  // ---- Layer 5: shorteners --------------------------------------------------
  modulesActive.push('shortener');
  if (isShortener(registrableDomain)) {
    const entry = shortenerEntry(registrableDomain!);
    reasons.push({
      code: 'shortener_unresolved',
      weight: 10,
      confidence: 'high',
      severity: 'info',
      data: { shortener: entry?.domain ?? registrableDomain ?? '', shortenerKey: entry?.nameKey ?? '' },
    });
  }

  // ---- Layer 6: observed redirect targets ----------------------------------
  if (opts.redirectTargets && opts.redirectTargets.length > 0) {
    modulesActive.push('redirects');
    const toKnownThreat = opts.redirectTargets.some((t) => {
      const p = parseTarget(t, resolvePublicSuffix);
      if (!p.hostname) return false;
      return p.hostname === hostname || (registrableDomain !== null && p.registrableDomain === registrableDomain);
    });
    if (toKnownThreat) {
      reasons.push({ code: 'redirect_to_threat', weight: 30, confidence: 'medium', severity: 'medium', data: {} });
    }
  }

  // ---- Coverage ------------------------------------------------------------
  const psl = pslStatus();
  if (psl.origin !== 'file') {
    reasons.push({ code: 'coverage.no_reputation_data', weight: 0, confidence: 'low', severity: 'info', data: { psl: psl.origin } });
  }
  if (!parsed.publicSuffix && !parsed.isIpLiteral) {
    reasons.push({ code: 'coverage.no_reputation_data', weight: 0, confidence: 'low', severity: 'info', data: { psl: 'unknown-suffix' } });
  }

  // ---- Verdict -------------------------------------------------------------
  const finalReasons = dedupeReasons(reasons);
  const score = computeScore(finalReasons);
  const verdict = decideVerdict({ knownMalicious, score, reasons: finalReasons, opts, parsed });

  if (!opts.settings.protectionEnabled) {
    return {
      verdict: 'not-analyzed',
      score: 0,
      confidence: 'high',
      registrableDomain,
      hostname,
      categories: [],
      reasons: [{ code: 'coverage.disabled_module', weight: 0, confidence: 'high', severity: 'info', data: {} }],
      sources: [],
      allowlisted,
      modulesActive: [],
      analyzedAt,
    };
  }

  return {
    verdict,
    score: verdict === 'known-malicious' ? 100 : score,
    confidence: knownMalicious ? 'high' : confidenceFromScore(score),
    registrableDomain,
    hostname,
    categories: [...categories],
    reasons: finalReasons,
    sources,
    allowlisted,
    modulesActive,
    analyzedAt,
  };
}

function computeScore(reasons: readonly RiskReason[]): number {
  let total = 0;
  for (const r of reasons) {
    if (r.weight <= 0) continue;
    // Confidence discounts the contribution: a low-confidence observation is
    // worth a fraction of its nominal weight.
    const factor = r.confidence === 'high' ? 1 : r.confidence === 'medium' ? 0.6 : 0.3;
    total += r.weight * factor;
  }
  return Math.min(SCORE_CAP, Math.round(total));
}

function decideVerdict(args: {
  knownMalicious: boolean;
  score: number;
  reasons: readonly RiskReason[];
  opts: AnalyzeOptions;
  parsed: ParsedTarget;
}): RiskVerdict {
  const { knownMalicious, score, reasons, opts, parsed } = args;

  if (!opts.settings.phishingEngineEnabled) return 'not-analyzed';

  if (knownMalicious) return 'known-malicious';

  // The engine cannot vouch for hosts it has no data source for.
  const hasCoverage = parsed.publicSuffix !== null && !parsed.isIpLiteral;
  if (!hasCoverage) return 'not-analyzed';

  const hasEvidence = reasons.some((r) => r.weight > 0);
  if (!hasEvidence) return 'no-threat-found';

  return score >= SUSPICIOUS_THRESHOLD ? 'suspicious' : 'no-threat-found';
}

function notAnalyzed(analyzedAt: number, codes: RiskReason['code'][]): AnalysisResult {
  return {
    verdict: 'not-analyzed',
    score: 0,
    confidence: 'low',
    registrableDomain: null,
    hostname: null,
    categories: [],
    reasons: codes.map((code) => ({ code, weight: 0, confidence: 'low' as Confidence, severity: 'info' as const, data: {} })),
    sources: [],
    allowlisted: false,
    modulesActive: [],
    analyzedAt,
  };
}

/**
 * Recovers the UNICODE form of the host.
 *
 * `new URL()` immediately converts an IDN host to punycode, so the evidence we
 * need (fullwidth letters, Cyrillic look-alikes, bidi controls) is gone by the
 * time we look at `url.hostname`. We therefore slice the authority out of the
 * RAW input ourselves. When the input has no non-ASCII host we return the
 * already-normalized ASCII host.
 */
function extractUnicodeHost(input: unknown, asciiHost: string): string | null {
  if (typeof input !== 'string') return asciiHost;

  let rest = input.trim();
  const schemeEnd = rest.indexOf('://');
  if (schemeEnd >= 0) rest = rest.slice(schemeEnd + 3);

  // Authority ends at the first path, query or fragment delimiter.
  rest = rest.split(/[/?#]/)[0] ?? '';

  // Strip credentials and the port.
  const at = rest.lastIndexOf('@');
  if (at >= 0) rest = rest.slice(at + 1);
  rest = rest.replace(/:\d+$/, '');

  if (rest.length === 0) return asciiHost;
  return /[^\x00-\x7F]/.test(rest) ? rest.toLowerCase() : asciiHost;
}
