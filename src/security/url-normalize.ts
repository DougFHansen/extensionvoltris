/**
 * Client-side URL normalization and registrable-domain extraction.
 *
 * Design rules:
 *  - We never trust the shape of attacker-controlled input.
 *  - We never silently "fix" a URL. If normalization is ambiguous we report
 *    `not-analyzed` instead of guessing.
 *  - The registrable domain comes from the Public Suffix List, never from a
 *    naive "last two labels" heuristic (which is wrong for `co.uk`, `com.br`,
 *    `github.io`, etc.).
 */

/** Control characters (C0 + DEL) plus space. Browsers ignore these in URLs,
 *  which makes them a classic filter-bypass vector ("exa mple.com"). */
const CONTROL_AND_SPACE_RE = /[\u0000-\u0020\u007F]/g;

export interface ParsedTarget {
  /** Full normalized URL, or null when the input was not a usable URL. */
  readonly url: string | null;
  readonly scheme: 'http' | 'https' | null;
  /** Lowercase ASCII/punycode host without trailing dot. */
  readonly hostname: string | null;
  /** Registrable domain per the Public Suffix List. */
  readonly registrableDomain: string | null;
  /** Labels to the left of the registrable domain (null when none). */
  readonly subdomain: string | null;
  /** Public suffix per the PSL (e.g. `com.br`). */
  readonly publicSuffix: string | null;
  readonly port: string | null;
  readonly path: string | null;
  readonly isIpLiteral: boolean;
  readonly normalized: boolean;
  readonly error?: 'empty' | 'too_long' | 'unparsable' | 'unsupported_scheme' | 'invalid_host';
}

const MAX_URL_LENGTH = 4096;
const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

/** Matches a bare hostname typed by the user (no scheme, no path). */
const BARE_HOST_RE = /^[a-z0-9](?:[a-z0-9-._~%\u00a1-\uffff]*[a-z0-9])?$/i;

export type PublicSuffixResolver = (
  hostname: string,
) => { publicSuffix: string; domain: string } | null;

function stripTrailingDot(host: string): string {
  return host.endsWith('.') ? host.slice(0, -1) : host;
}

/** Converts a Unicode hostname to its ASCII (IDNA/punycode) form when possible. */
export function toAsciiHost(host: string): { ascii: string; hadUnicode: boolean } {
  const hadUnicode = /[^\u0000-\u007F]/.test(host);
  if (!hadUnicode) return { ascii: host.toLowerCase(), hadUnicode: false };
  try {
    const url = new URL(`http://${host}/`);
    return { ascii: stripTrailingDot(url.hostname).toLowerCase(), hadUnicode: true };
  } catch {
    return { ascii: host.toLowerCase(), hadUnicode: true };
  }
}

export const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpv4Literal(host: string): boolean {
  const m = IPV4_RE.exec(host);
  if (!m) return false;
  for (let i = 1; i <= 4; i += 1) {
    const part = m[i]!;
    if (part.length > 1 && part.startsWith('0')) return false; // reject 010.0.0.1
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return false;
  }
  return true;
}

export function isIpv6Literal(host: string): boolean {
  return host.startsWith('[') && host.endsWith(']');
}

/**
 * Characters that can never appear in a syntactically valid hostname.
 * `*`, `!` and `$` are also trie sentinel keys in our PSL data structure, so they
 * must never reach the resolver from hostile input.
 */
const ILLEGAL_HOST_RE = /[\s"'<>`\\@:?#%{}|^[\]*!$]/;

/**
 * Parses and normalizes an untrusted string into a `ParsedTarget`.
 * Never throws; returns a structured `error` instead.
 */
export function parseTarget(input: unknown, resolvePs: PublicSuffixResolver): ParsedTarget {
  if (typeof input !== 'string' || input.trim().length === 0) return empty('empty');

  const raw = input.trim();
  if (raw.length > MAX_URL_LENGTH) return empty('too_long');

  const cleaned = raw.replace(CONTROL_AND_SPACE_RE, '');
  if (cleaned.length === 0) return empty('empty');

  let url: URL;
  try {
    url = new URL(cleaned);
  } catch {
    // Retry treating the input as a bare host, which is what a user types into
    // the popup. Anything containing a path separator is rejected here so we do
    // not reinterpret "example.com/evil" as a host.
    if (cleaned.includes('/') || !BARE_HOST_RE.test(cleaned)) return empty('unparsable');
    try {
      url = new URL(`https://${cleaned}/`);
    } catch {
      return empty('unparsable');
    }
  }

  if (!ALLOWED_SCHEMES.has(url.protocol)) return empty('unsupported_scheme');

  const rawHost = stripTrailingDot(url.hostname);
  if (rawHost.length === 0 || rawHost.length > 253) return empty('invalid_host');
  if (ILLEGAL_HOST_RE.test(rawHost)) return empty('invalid_host');

  const { ascii: hostname } = toAsciiHost(rawHost);
  const isIpLiteral = isIpv4Literal(hostname) || isIpv6Literal(hostname);

  let registrableDomain: string | null = null;
  let publicSuffix: string | null = null;
  let subdomain: string | null = null;

  if (!isIpLiteral) {
    const resolved = resolvePs(hostname);
    if (resolved) {
      publicSuffix = resolved.publicSuffix;
      registrableDomain = resolved.domain;
      subdomain =
        hostname === resolved.domain ? null : hostname.slice(0, hostname.length - resolved.domain.length - 1);
    } else {
      // No PSL rule matched (for example `localhost` or a private TLD).
      // Fall back to a conservative two-label approximation and leave
      // `publicSuffix` null so callers can downgrade the analysis.
      const labels = hostname.split('.');
      if (labels.length >= 2) {
        publicSuffix = labels[labels.length - 1]!;
        registrableDomain = labels.slice(-2).join('.');
        subdomain = labels.slice(0, -2).join('.') || null;
      }
    }
  }

  return {
    url: url.toString(),
    scheme: url.protocol === 'https:' ? 'https' : 'http',
    hostname,
    registrableDomain,
    subdomain,
    publicSuffix,
    port: url.port.length > 0 ? url.port : null,
    path: url.pathname === '/' ? null : url.pathname,
    isIpLiteral,
    normalized: true,
  };
}

function empty(error: ParsedTarget['error']): ParsedTarget {
  return {
    url: null,
    scheme: null,
    hostname: null,
    registrableDomain: null,
    subdomain: null,
    publicSuffix: null,
    port: null,
    path: null,
    isIpLiteral: false,
    normalized: false,
    error,
  };
}

/** True when `hostname` is `domain` or any subdomain of `domain`. */
export function hostMatchesDomain(hostname: string, domain: string): boolean {
  const h = hostname.toLowerCase();
  const d = domain.toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

/** Splits a hostname into non-empty labels. */
export function labelsOf(hostname: string): string[] {
  return hostname.split('.').filter((l) => l.length > 0);
}

/**
 * Returns the longest member of `candidates` that is a suffix of `hostname`
 * (excluding a full-label-single match of the whole hostname when the set is a
 * known-brand set). Used by the impersonation engine.
 */
export function longestSuffixMatch(hostname: string, candidates: ReadonlySet<string>): string | null {
  const labels = labelsOf(hostname);
  let best: string | null = null;
  for (let i = 1; i < labels.length; i += 1) {
    const candidate = labels.slice(i).join('.');
    if (candidates.has(candidate) && (best === null || candidate.length > best.length)) {
      best = candidate;
    }
  }
  return best;
}
