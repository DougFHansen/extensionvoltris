/**
 * URL shape heuristics and brand-impersonation detection.
 *
 * These heuristics NEVER produce a "known malicious" verdict on their own. Their
 * output is a set of weighted, explained reasons consumed by the risk engine,
 * which is the only place allowed to map evidence onto a verdict.
 *
 * False-positive policy (Section 2 of the specification):
 *  - Missing HTTPS is NOT a threat signal.
 *  - Many subdomains is NOT a threat signal.
 *  - The word "login" is NOT a threat signal.
 */
import { BRAND_ALLOW_EXCEPTIONS, BRAND_DOMAIN_INDEX, BRAND_KEYWORDS, type BrandEntry } from './brands';
import { labelsOf } from './url-normalize';
import type { RiskReason } from '../core/types';

/** High-entropy TLDs commonly abused for phishing campaigns. */
const HIGH_RISK_TLDS = new Set(['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'click', 'link', 'work', 'country', 'kim', 'rest', 'loan', 'download', 'stream', 'racing', 'party', 'date', 'faith', 'review', 'science', 'cricket', 'accountant', 'bid', 'trade', 'win', 'men', 'zip', 'mov']);

export interface ImpersonationMatch {
  readonly brand: BrandEntry;
  readonly kind: 'subdomain' | 'keyword';
  /** Label that triggered the match. */
  readonly label: string;
  readonly confidence: 'high' | 'medium' | 'low';
}

/**
 * Detects a protected brand used as a DECOY inside an attacker-controlled host.
 *
 * Examples caught:
 *   paypal.com.secure-login.tk       -> brand occupies the LEADING labels
 *   login.paypal.com.br-secure.tk    -> brand is stranded in the middle
 *   secure.paypal.evil               -> brand keyword glued to a subdomain
 *
 * Examples deliberately NOT flagged:
 *   paypal.com                       -> the brand's own domain
 *   www.paypal.com                   -> the brand's own subdomain
 *   googleadservices.com              -> allow-exception list
 *   user.github.io                   -> public suffix, resolved by the PSL
 */
export function detectImpersonation(
  hostname: string,
  registrableDomain: string | null,
): { matches: readonly ImpersonationMatch[]; reasons: readonly RiskReason[] } {
  const matches: ImpersonationMatch[] = [];
  const reasons: RiskReason[] = [];
  if (!registrableDomain) return { matches, reasons };

  const labels = labelsOf(hostname);
  if (labels.length < 2) return { matches, reasons };

  // The brand's own domain, and any subdomain of it, is legitimate.
  for (const brand of BRAND_DOMAIN_INDEX.values()) {
    if (hostname === brand.domain || hostname.endsWith(`.${brand.domain}`)) return { matches, reasons };
  }
  if (BRAND_ALLOW_EXCEPTIONS.has(registrableDomain) || BRAND_ALLOW_EXCEPTIONS.has(hostname)) {
    return { matches, reasons };
  }

  // 1. A protected domain appears as a CONTIGUOUS label run that is NOT the tail
  //    of the host. That is the defining shape of a decoy brand.
  for (const brand of BRAND_DOMAIN_INDEX.values()) {
    const window = brand.domain.split('.');
    const width = window.length;
    if (labels.length <= width) continue;

    let found = false;
    for (let start = 0; start + width <= labels.length; start += 1) {
      const slice = labels.slice(start, start + width);
      if (!slice.every((label, i) => label === window[i])) continue;
      // A run that reaches the end of the host is the brand's own domain.
      if (start + width === labels.length) continue;
      found = true;
      matches.push({
        brand,
        kind: 'subdomain',
        label: slice.join('.'),
        confidence: brand.weight === 'critical' ? 'high' : 'medium',
      });
      reasons.push({
        code: 'brand_impersonation_subdomain',
        weight: brand.weight === 'critical' ? 62 : 48,
        confidence: brand.weight === 'critical' ? 'high' : 'medium',
        severity: brand.weight === 'critical' ? 'high' : 'medium',
        data: { brand: brand.domain, brandKey: brand.nameKey, matched: slice.join('.') },
      });
      break;
    }
    if (found) break; // one impersonation match is enough; more would double-count
  }

  // 2. Brand keyword glued into the registrable domain we do not own.
  const rdLabels = labelsOf(registrableDomain);
  const rdLabelSet = new Set(rdLabels);
  for (const keyword of BRAND_KEYWORDS) {
    if (!rdLabelSet.has(keyword)) continue;
    if (BRAND_DOMAIN_INDEX.has(registrableDomain)) continue;
    const brandEntry = [...BRAND_DOMAIN_INDEX.values()].find((b) => b.domain.includes(keyword));
    // Only fire when the keyword label is glued to something else (hyphen/prefix)
    // or the registrable domain is clearly third-party.
    const glued = rdLabels.some(
      (l) => l !== keyword && (l.includes(keyword) || keyword.includes(l)) && Math.abs(l.length - keyword.length) <= 3,
    );
    if (!glued && !brandEntry) continue;
    if (!glued && brandEntry && rdLabels.length <= 2) continue;

    matches.push({ brand: brandEntry ?? { domain: keyword, nameKey: '', weight: 'high' }, kind: 'keyword', label: keyword, confidence: 'medium' });
    reasons.push({
      code: 'brand_keyword_in_host',
      weight: brandEntry?.weight === 'critical' ? 34 : 22,
      confidence: 'medium',
      severity: 'medium',
      data: { keyword, brand: brandEntry?.domain ?? keyword, brandKey: brandEntry?.nameKey ?? '' },
    });
    break;
  }

  return { matches, reasons };
}

export interface ShapeSignals {
  readonly reasons: readonly RiskReason[];
  /** Signals that are informational only and never influence the score. */
  readonly notes: readonly string[];
}

/**
 * Structural URL signals. Every reason carries an explicit explanation so the
 * user can judge for themselves; nothing here is presented as proof.
 */
export function analyzeUrlShape(parsed: {
  readonly hostname: string | null;
  readonly registrableDomain: string | null;
  readonly publicSuffix: string | null;
  readonly subdomain: string | null;
  readonly path: string | null;
  readonly isIpLiteral: boolean;
  readonly url: string | null;
  readonly scheme: 'http' | 'https' | null;
  readonly port: string | null;
}): ShapeSignals {
  const reasons: RiskReason[] = [];
  const notes: string[] = [];

  const { hostname, registrableDomain, publicSuffix, subdomain, path, isIpLiteral } = parsed;
  if (!hostname) return { reasons, notes };

  // A bare IP literal in place of a domain is a meaningful signal, but plenty of
  // legitimate services use it, so it is weighted low and never auto-blocks.
  if (isIpLiteral) {
    reasons.push({
      code: 'ip_literal_host',
      weight: 20,
      confidence: 'medium',
      severity: 'low',
      data: {},
    });
  }

  const rdLabels = registrableDomain ? labelsOf(registrableDomain) : [];
  const tld = publicSuffix ?? (rdLabels.length > 0 ? rdLabels[rdLabels.length - 1]! : '');
  if (tld && HIGH_RISK_TLDS.has(tld)) {
    reasons.push({
      code: 'suspicious_tld_risk',
      weight: 18,
      confidence: 'low',
      severity: 'low',
      data: { tld },
    });
  }

  // Credential harvesters commonly put the action in the path or use a data URI
  // style landing page. `login` ALONE is never a signal - we require an
  // authentication keyword AND an unrelated/deceptive context.
  const suspiciousPathTokens = ['verify', 'verification', 'confirm-account', 'secure-login', 'webscr', 'signin', 'auth-confirm', 'unlock', 'recuperar-senha', 'atualize-dados'];
  if (path) {
    const lower = path.toLowerCase();
    const hit = suspiciousPathTokens.find((t) => lower.includes(t));
    if (hit && rdLabels.length >= 1) {
      const ownsPathKeyword = rdLabels.some((l) => l.includes(hit.split('-')[0] ?? hit));
      if (!ownsPathKeyword) {
        reasons.push({
          code: 'suspicious_url_shape',
          weight: 12,
          confidence: 'low',
          severity: 'info',
          data: { token: hit },
        });
      }
    }
  }

  // Excessive subdomain depth is a weak signal ONLY when combined with a brand
  // keyword. Standalone it produces a note, never a score.
  const depth = subdomain ? labelsOf(subdomain).length : 0;
  if (depth >= 4) {
    notes.push('deep_subdomain');
  }

  // Non-standard ports are common in development and rarely malicious.
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    notes.push('non_standard_port');
  }

  return { reasons, notes };
}
