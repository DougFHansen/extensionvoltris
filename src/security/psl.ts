/**
 * Public Suffix List resolver.
 *
 * The list is shipped as a data file (`psl.json`) and loaded LAZILY on first
 * use, then cached in memory for the lifetime of the service worker. This keeps
 * cold-start of the event-driven service worker at effectively zero cost, which
 * is a hard requirement (Section 11 of the specification).
 *
 * A compact fallback table is compiled into the bundle so that analysis still
 * produces a usable result if the data file is unavailable (for example during a
 * partial install). When the fallback is in play the analysis engine lowers
 * confidence and Diagnostics reports which dataset was used.
 */
import type { PublicSuffixResolver } from './url-normalize';
import { labelsOf } from './url-normalize';

/**
 * Recursive trie node.
 *
 * Encoding (see `scripts/generate-psl.mjs`):
 *   `$`  -> this node is a public-suffix rule
 *   `!`  -> this node is an EXCEPTION rule (prevailing suffix is one label less)
 *   `*`  -> child key matching any single label
 *   `!$` -> a literal label named `!` cannot occur in a hostname, and hostile
 *          hosts containing `!`, `*` or `$` are rejected by `parseTarget`
 *          before reaching this resolver.
 */
interface PslNodeObject {
  $?: 1;
  '!'?: 1;
  [label: string]: 1 | PslNodeObject | undefined;
}

type PslNode = 1 | PslNodeObject;

export interface PslMetadata {
  readonly source: string;
  readonly license: string;
  readonly sha256: string;
  readonly generatedAt: string;
  readonly ruleCount: number;
}

interface PslData extends PslMetadata {
  readonly schemaVersion: number;
  readonly root: PslNode;
}

export type PslOrigin = 'file' | 'fallback' | 'pending';

/**
 * Conservative fallback: only suffixes that would otherwise be misparsed as part
 * of a registrable domain. Deliberately short - when this table is all we have,
 * callers downgrade confidence instead of pretending to be precise.
 */
const FALLBACK_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.tr', 'com.tw', 'com.hk', 'com.sg',
  'co.kr', 'or.kr', 'go.kr', 'co.nz', 'co.za', 'com.ua', 'com.pl', 'com.es',
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app',
  'herokuapp.com', 'web.app', 'firebaseapp.com', 'blogspot.com', 'wordpress.com',
  's3.amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'appspot.com',
  'online', 'site', 'shop', 'store', 'xyz', 'top', 'click', 'link', 'gq', 'cf', 'tk', 'ml',
]);

let root: PslNode | null = null;
let origin: PslOrigin = 'pending';
let metadata: PslMetadata | null = null;
let loadPromise: Promise<void> | null = null;

export function pslStatus(): { origin: PslOrigin; ruleCount: number; metadata: PslMetadata | null } {
  return { origin, ruleCount: root ? metadata?.ruleCount ?? 0 : FALLBACK_SUFFIXES.size, metadata };
}

/** Kicks off the lazy load. Fire-and-forget during service worker startup. */
export function preloadPsl(): void {
  void loadPsl();
}

export async function loadPsl(): Promise<void> {
  if (origin !== 'pending') return;
  if (loadPromise) return loadPromise;
  loadPromise = (async () => {
    try {
      const res = await fetch(chrome.runtime.getURL('psl.json'));
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as PslData;
      if (data.schemaVersion !== 1 || typeof data.root !== 'object' || data.root === null) {
        throw new Error('unexpected PSL schema version');
      }
      if (typeof data.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.sha256)) {
        throw new Error('missing or malformed checksum');
      }
      root = data.root;
      origin = 'file';
      metadata = {
        source: data.source,
        license: data.license,
        sha256: data.sha256,
        generatedAt: data.generatedAt,
        ruleCount: data.ruleCount,
      };
    } catch {
      root = null;
      origin = 'fallback';
    }
  })();
  return loadPromise;
}

function resolveWithFallback(hostname: string): { publicSuffix: string; domain: string } | null {
  const labels = labelsOf(hostname);
  if (labels.length < 2) return null;

  let best: string | null = null;
  for (let i = 1; i < labels.length; i += 1) {
    const candidate = labels.slice(i).join('.');
    if (FALLBACK_SUFFIXES.has(candidate) && (best === null || candidate.length > best.length)) best = candidate;
  }

  // No explicit rule matched, so apply the PSL's implicit prevailing rule `*`:
  // the public suffix is the last label. Without this the fallback would treat
  // `sub.example.com` as the registrable domain, which is wrong for every
  // ordinary domain.
  const suffix = best ?? labels[labels.length - 1]!;
  const suffixLabels = labelsOf(suffix).length;
  const domainLabels = labels.slice(labels.length - (suffixLabels + 1)).join('.');
  return domainLabels.length > 0 ? { publicSuffix: suffix, domain: domainLabels } : null;
}

interface ScanResult {
  /** Deepest matching NORMAL rule, expressed as a label count. -1 when none. */
  normal: number;
  /** Deepest matching EXCEPTION rule, expressed as a label count. -1 when none. */
  exception: number;
}

/**
 * Walks the trie from the TLD downwards.
 *
 * `consumed` is the number of labels already matched when we ARRIVE at `node`.
 * Because the trie is stored TLD-first, the label at position `consumed` is
 * `labels[labels.length - 1 - consumed]`.
 *
 * The PSL specification says the prevailing rule is "the one with the most
 * labels", which is what `normal` / `exception` track.
 */
function scanNode(node: PslNode | undefined, labels: string[], consumed: number): ScanResult {
  const result: ScanResult = { normal: -1, exception: -1 };
  if (node === undefined || typeof node === 'number') return result;

  if (node.$ === 1) result.normal = consumed;

  const nextConsumed = consumed + 1;
  const canDescend = nextConsumed < labels.length;
  const currentLabel = labels[labels.length - 1 - consumed] ?? '';

  const consider = (child: PslNode | undefined): void => {
    if (child === undefined) return;

    const isException = typeof child !== 'number' && child['!'] === 1;
    const isRule = typeof child === 'number' || child.$ === 1;

    let matchDepth = -1;
    if (isRule || isException) matchDepth = nextConsumed;

    if (canDescend) {
      const sub = scanNode(child, labels, nextConsumed);
      if (sub.normal > matchDepth) matchDepth = sub.normal;
      if (sub.exception > result.exception) result.exception = sub.exception;
    }

    if (isException) {
      if (matchDepth > result.exception) result.exception = matchDepth;
    } else if (matchDepth > result.normal) {
      result.normal = matchDepth;
    }
  };

  consider(node[currentLabel]);
  consider(node['*']);

  return result;
}

/**
 * Synchronous resolver handed to `parseTarget`.
 *
 * When the PSL data file has not loaded yet we use the compact fallback table
 * and return `null` if it has no opinion, which makes `parseTarget` fall back to
 * a two-label approximation. `pslStatus()` is surfaced in Diagnostics and the
 * analysis engine lowers confidence when `origin !== 'file'`.
 */
export const resolvePublicSuffix: PublicSuffixResolver = (hostname: string) => {
  const labels = labelsOf(hostname);
  if (labels.length < 2) return null;

  if (root === null) {
    return resolveWithFallback(hostname);
  }

  const { normal, exception } = scanNode(root, labels, 0);
  let suffixLength: number;
  if (exception > 0) suffixLength = Math.max(1, exception - 1);
  else if (normal > 0) suffixLength = normal;
  else suffixLength = 1; // implicit prevailing rule `*`

  if (labels.length <= suffixLength) {
    // The host IS a public suffix; there is no registrable domain to report.
    return { publicSuffix: labels.slice(labels.length - suffixLength).join('.'), domain: '' };
  }
  return {
    publicSuffix: labels.slice(labels.length - suffixLength).join('.'),
    domain: labels.slice(labels.length - suffixLength - 1).join('.'),
  };
};

export function resetPslForTests(): void {
  root = null;
  origin = 'pending';
  metadata = null;
  loadPromise = null;
}

export function setPslRootForTests(node: PslNode, meta?: PslMetadata): void {
  root = node;
  origin = 'file';
  metadata = meta ?? { source: 'test', license: 'MPL-2.0', sha256: '0'.repeat(64), generatedAt: '2026-01-01', ruleCount: 0 };
}
