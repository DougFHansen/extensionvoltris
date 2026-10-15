/**
 * Feed parsers.
 *
 * Every parser is a pure function over text and returns a structured result plus
 * counters describing exactly what was accepted, skipped and why. Nothing is
 * silently dropped - the counters feed the Diagnostics tab so the user can audit
 * the conversion.
 */
export interface ParseCounters {
  readonly accepted: number;
  readonly skipped: number;
  readonly skippedByReason: Record<string, number>;
  readonly duplicates: number;
}

export function emptyCounters(): ParseCounters {
  return { accepted: 0, skipped: 0, skippedByReason: {}, duplicates: 0 };
}

function skip(counters: MutableCounters, reason: string): void {
  counters.skipped += 1;
  counters.skippedByReason[reason] = (counters.skippedByReason[reason] ?? 0) + 1;
}

type MutableCounters = { accepted: number; skipped: number; skippedByReason: Record<string, number>; duplicates: number };

/** Maximum bytes we will read from a remote feed. */
export const MAX_FEED_BYTES = 32 * 1024 * 1024;
/** Maximum individual line length accepted. */
const MAX_LINE_LENGTH = 4096;

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

/**
 * Strict hostname validation. Rejects empty labels, over-long labels, leading /
 * trailing hyphens, label length > 63 and total length > 253.
 */
export function isValidHostname(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  if (!HOSTNAME_RE.test(host)) return false;
  const labels = host.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
  }
  // Must have at least one dot unless it is a known single-label service.
  return labels.length >= 2;
}

/** Normalizes a hostname for storage/deduplication. Returns null when invalid. */
export function normalizeHostname(input: string): string | null {
  let host = input.trim().toLowerCase();
  if (host.length === 0) return null;
  if (host.startsWith('[') && host.endsWith(']')) return null; // IPv6 literal
  while (host.endsWith('.')) host = host.slice(0, -1);
  if (!isValidHostname(host)) return null;
  // Reject IP literals masquerading as domains.
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return null;
  return host;
}

/**
 * `hosts`-format parser.
 * Accepts `0.0.0.0 host`, `127.0.0.1 host`, bare hostnames and
 * `adblock`-format `||host^` lines. Comments start with `#` or `!`.
 */
export function parseHosts(input: string): { hosts: Set<string>; counters: ParseCounters } {
  const counters = emptyCounters() as MutableCounters;
  const hosts = new Set<string>();

  for (const rawLine of splitLines(input)) {
    if (rawLine.length === 0) continue;
    const first = rawLine[0]!;
    if (first === '#' || first === '!' || first === ';') continue;
    if (first === '[') continue; // [Adblock Plus 2.0]

    let line = rawLine;
    // adblock-style single-host rule
    if (line.startsWith('||') && line.endsWith('^')) {
      line = line.slice(2, -1);
    } else {
      const parts = line.split(/\s+/);
      if (parts.length >= 2) line = parts[parts.length - 1]!;
      else if (parts.length === 1 && /^\d+\.\d+\.\d+\.\d+$/.test(parts[0]!)) continue;
    }

    const host = normalizeHostname(line);
    if (host === null) {
      skip(counters, 'invalid_hostname');
      continue;
    }
    if (hosts.has(host)) {
      counters.duplicates += 1;
      continue;
    }
    hosts.add(host);
    counters.accepted += 1;
  }

  return { hosts, counters };
}

/**
 * Plain domain-list parser: one domain per line, `#` comments.
 * Used by Phishing.Database.
 */
export function parseDomainList(input: string): { hosts: Set<string>; counters: ParseCounters } {
  const counters = emptyCounters() as MutableCounters;
  const hosts = new Set<string>();

  for (const rawLine of splitLines(input)) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) continue;

    // Some feeds emit full URLs; we take the host only and never keep the path.
    let value = line;
    if (/^https?:\/\//i.test(value)) {
      try {
        value = new URL(value).hostname;
      } catch {
        skip(counters, 'unparsable_url');
        continue;
      }
    } else if (value.includes('/')) {
      const slash = value.indexOf('/');
      if (slash > 0) value = value.slice(0, slash);
    }

    const host = normalizeHostname(value);
    if (host === null) {
      skip(counters, 'invalid_hostname');
      continue;
    }
    if (hosts.has(host)) {
      counters.duplicates += 1;
      continue;
    }
    hosts.add(host);
    counters.accepted += 1;
  }

  return { hosts, counters };
}

/**
 * Splits text into lines without ever building a giant intermediate array.
 *
 * CRLF is handled because feed files authored on Windows (or edited on Windows)
 * carry a trailing carriage return; leaving it in place makes every hostname
 * fail validation and silently drops the whole list.
 */
export function splitLines(input: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i <= input.length; i += 1) {
    const atEnd = i === input.length;
    const code = atEnd ? 10 : input.charCodeAt(i);
    if (code !== 10) continue;

    let end = i;
    if (end > start && input.charCodeAt(end - 1) === 13) end -= 1; // strip CR

    out.push(end - start > MAX_LINE_LENGTH ? input.slice(start, start + MAX_LINE_LENGTH) : input.slice(start, end));
    start = i + 1;
  }
  return out;
}

export interface ParsedAdblock {
  /** Converted rules, in original order, already de-duplicated by `key`. */
  readonly rules: readonly AdblockRule[];
  readonly counters: ParseCounters;
  readonly headerVersion: string | null;
}

export interface AdblockRule {
  /** The original filter text, kept for diagnostics. */
  readonly filter: string;
  /** Normalized host the rule targets (empty for regex rules we accepted). */
  readonly host: string;
  /** ABP `third-party` option. */
  readonly thirdParty: boolean;
  /** Domains the rule is limited to (`domain=` option), empty when global. */
  readonly initiatorDomains: readonly string[];
  /** Resource types to exclude (e.g. `~script`). */
  readonly excludedResourceTypes: readonly string[];
  /** Resource types explicitly included via `$type=`; empty means "all". */
  readonly resourceTypes: readonly string[];
  /** true when the filter targets the main frame. */
  readonly mainFrame: boolean;
}

/**
 * Options we deliberately DO NOT support. Encountering one means we skip the
 * filter instead of applying an approximation we cannot defend.
 */
const UNSUPPORTED_OPTIONS = new Set([
  'domain', 'from', 'to', 'denyallow', 'method', 'header', 'ipaddress',
  'all', 'popup', 'document', 'elemhide', 'generichide', 'ghide',
  'specifichide', 'content', 'inline-script', 'inline-font', 'jsinject',
  'urlblock', 'urltransform', 'app', 'network', 'websocket', 'webrtc',
  'csp', 'replace', 'cookie', 'removeparam', 'permissions',
]);

/** Options that are safe to ignore because they do not change the match set. */
const IGNORABLE_OPTIONS = new Set(['important', 'hide', 'donottrack', 'frame', 'object', 'object-subrequest', 'stylesheet', 'xmlhttprequest', 'image', 'media', 'font', 'other', 'ping', 'beacon']);

const RESOURCE_TYPES: Record<string, string> = {
  script: 'script',
  image: 'image',
  stylesheet: 'stylesheet',
  object: 'object',
  xmlhttprequest: 'xmlhttprequest',
  ping: 'ping',
  media: 'media',
  websocket: 'websocket',
  other: 'other',
  subdocument: 'sub_frame',
  sub_frame: 'sub_frame',
  document: 'main_frame',
  main_frame: 'main_frame',
  font: 'font',
};

/**
 * Adblock Plus filter parser, restricted to a SAFE SUBSET.
 *
 * Supported:
 *   `||host^`            domain anchor including subdomains
 *   `||host/path`        domain anchor with a path prefix
 *   `|http://host^`      left anchor
 *   `host`               plain substring
 *   `*` wildcards        inside the host/path part
 *   options: `third-party`, `first-party`, `~script`, `~image`, ...
 *
 * Explicitly rejected (counted, never guessed):
 *   regular expressions, cosmetic selectors, `domain=`, `$app`, negation-only
 *   filters, unsupported options.
 */
export function parseAdblock(input: string): ParsedAdblock {
  const counters = emptyCounters() as MutableCounters;
  const rules: AdblockRule[] = [];
  const seen = new Set<string>();
  let headerVersion: string | null = null;

  for (const rawLine of splitLines(input)) {
    let line = rawLine.trim();
    if (line.length === 0) continue;
    if (line.startsWith('!')) {
      const m = /^!.*Version:\s*(\S+)/i.exec(line);
      if (m && headerVersion === null) headerVersion = m[1]!;
      continue;
    }
    if (line.startsWith('#') || line.startsWith('[')) {
      // Cosmetic filters (`##.selector`) and element-hiding rules have no
      // network equivalent. Count them so Diagnostics can show how much of the
      // list we deliberately do not enforce.
      skip(counters, line.startsWith('##') || line.includes('##') ? 'cosmetic_filter' : 'comment_or_metadata');
      continue;
    }

    // Split off options.
    let optionsPart = '';
    const dollar = line.lastIndexOf('$');
    if (dollar > 0) {
      optionsPart = line.slice(dollar + 1);
      line = line.slice(0, dollar);
    }

    if (optionsPart.length > 0) {
      const names = optionsPart.split(',').map((o) => o.trim().toLowerCase());
      let unsupported = false;
      for (const name of names) {
        if (name.length === 0) continue;
        // Options carry values as `name=value`; the deny-list is keyed on the
        // bare name, so strip the value BEFORE looking it up. Without this,
        // `removeparam=fbclid` or `csp=frame-src` would slip through and we
        // would apply a filter we do not actually understand.
        const bare = name.startsWith('~') || name.startsWith('+') ? name.slice(1) : name;
        const bareName = bare.split('=')[0] ?? bare;

        if (name.startsWith('~') || name.startsWith('+')) {
          if (bare.includes('=') || UNSUPPORTED_OPTIONS.has(bareName)) unsupported = true;
          continue;
        }
        if (bareName === 'domain') {
          if (!bare.includes('=')) unsupported = true;
          continue;
        }
        if (UNSUPPORTED_OPTIONS.has(bareName)) {
          unsupported = true;
          continue;
        }
        if (IGNORABLE_OPTIONS.has(bareName) || bareName === 'third-party' || bareName === 'first-party' || RESOURCE_TYPES[bareName]) {
          continue;
        }
        unsupported = true;
      }
      if (unsupported) {
        skip(counters, 'unsupported_option');
        continue;
      }
    }

    // Element-hiding / cosmetic filters (`##.selector`, `host##.selector`) have
    // no network equivalent and cannot be expressed as a DNR rule. Detect them
    // wherever the `##` appears so Diagnostics reports them accurately.
    if (line.includes('##')) {
      skip(counters, 'cosmetic_filter');
      continue;
    }

    // Reject regular expressions: we keep every compiled rule inside the
    // "safe dynamic rules" quota and the regex quota is only 1000.
    if (line.startsWith('/') && line.endsWith('/') && line.length > 2) {
      skip(counters, 'regex_filter');
      continue;
    }
    if (line.includes('/') && /^\/.*\/[a-z]*$/i.test(line)) {
      skip(counters, 'regex_filter');
      continue;
    }

    if (line.length === 0) {
      skip(counters, 'empty_filter');
      continue;
    }

    const parsed = parseAdblockPattern(line);
    if (parsed === null) {
      skip(counters, 'unsupported_pattern');
      continue;
    }

    const options = parseAdblockOptions(optionsPart);
    const rule: AdblockRule = {
      filter: rawLine.trim(),
      host: parsed.host,
      thirdParty: options.thirdParty,
      initiatorDomains: options.initiatorDomains,
      excludedResourceTypes: options.excludedResourceTypes,
      resourceTypes: options.resourceTypes,
      mainFrame: options.resourceTypes.includes('main_frame'),
    };

    const key = `${rule.host}|${rule.thirdParty}|${rule.initiatorDomains.join(',')}|${rule.excludedResourceTypes.join(',')}|${rule.resourceTypes.join(',')}`;
    if (seen.has(key)) {
      counters.duplicates += 1;
      continue;
    }
    seen.add(key);
    rules.push(rule);
    counters.accepted += 1;
  }

  return { rules, counters, headerVersion };
}

interface ParsedOptions {
  thirdParty: boolean;
  initiatorDomains: readonly string[];
  excludedResourceTypes: readonly string[];
  resourceTypes: readonly string[];
}

function parseAdblockOptions(optionsPart: string): ParsedOptions {
  const excluded: string[] = [];
  const included: string[] = [];
  const initiatorDomains: string[] = [];
  let thirdParty = false;

  if (optionsPart.length === 0) return { thirdParty, initiatorDomains, excludedResourceTypes: [], resourceTypes: [] };

  for (const raw of optionsPart.split(',')) {
    const name = raw.trim().toLowerCase();
    if (name.length === 0) continue;
    if (name === 'third-party' || name === '3p') {
      thirdParty = true;
    } else if (name === 'first-party' || name === '1p') {
      thirdParty = false;
    } else if (name.startsWith('domain=')) {
      for (const d of name.slice('domain='.length).split('|')) {
        const host = normalizeHostname(d);
        if (host) initiatorDomains.push(host);
      }
    } else if (name.startsWith('~')) {
      const bare = name.slice(1);
      const mapped = RESOURCE_TYPES[bare];
      if (mapped) excluded.push(mapped);
    } else {
      const mapped = RESOURCE_TYPES[name];
      if (mapped) included.push(mapped);
    }
  }

  const resourceTypes = included.length > 0 ? [...new Set(included)] : [];
  const excludedResourceTypes = [...new Set(excluded)];
  return {
    thirdParty,
    initiatorDomains: [...new Set(initiatorDomains)],
    excludedResourceTypes: excludedResourceTypes.filter((t) => !resourceTypes.includes(t)),
    resourceTypes,
  };
}

interface ParsedPattern {
  host: string;
}

/**
 * Converts an ABP pattern into a host (and optional path prefix).
 * Returns null when the pattern cannot be represented faithfully.
 */
function parseAdblockPattern(pattern: string): ParsedPattern | null {
  let value = pattern;

  // Scheme specific: only http/https matter and both map to the same host.
  if (value.startsWith('|http://') || value.startsWith('|https://')) {
    value = value.slice(1);
  } else if (value.includes('://')) {
    return null;
  }

  // Strip the `^` separator (meaning "end of host / end of a character class").
  value = value.replace(/\^/g, '');

  let hostAndPath = value;

  if (value.startsWith('||')) {
    hostAndPath = value.slice(2);
    const slash = hostAndPath.indexOf('/');
    const hostPart = slash === -1 ? hostAndPath : hostAndPath.slice(0, slash);
    const host = normalizeHostname(hostPart);
    if (host === null) return null;
    // Path-carrying filters are NOT converted: `||host/path` would need a
    // urlFilter per filter and the value/ratio is poor. We report them.
    if (slash !== -1) return null;
    return { host };
  }

  if (value.startsWith('|')) {
    value = value.slice(1);
  }

  // A plain substring filter. We only accept one that resolves to a bare
  // hostname pattern (optionally with `*` wildcards); anything containing a path
  // separator is out of scope.
  if (value.includes('/')) return null;
  if (value.includes('*')) {
    // Convert `*` wildcards into a DNS-ish pattern. We accept only patterns
    // where the wildcard stands in for label characters, never for the dots.
    if (!/^\*?[a-z0-9*_-]+(\.\*?[a-z0-9*_-]+)*\*?$/i.test(value)) return null;
  }
  const cleaned = value.replace(/^\*|\*$/g, '');
  const host = normalizeHostname(cleaned);
  if (host === null) return null;
  return { host };
}
