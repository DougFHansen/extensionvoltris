/**
 * Known URL shorteners.
 *
 * The engine NEVER auto-expands a shortener in v1: doing so would require either
 * fetching the destination (a network request driven by page content, which
 * leaks browsing to third parties and is a classic SSRF-style amplification
 * vector) or a remote resolution API (which would ship browsing data to a
 * server - explicitly forbidden by Section 9).
 *
 * Instead, a shortener destination is surfaced as an informational signal: the
 * user sees that the real destination is hidden and must inspect it manually.
 * The link inspector offers an explicit, user-initiated "reveal destination"
 * action that performs a single HEAD-less navigation attempt in a background tab
 * only when the user clicks it.
 */

export interface ShortenerEntry {
  readonly domain: string;
  /** i18n key for the UI. */
  readonly nameKey: string;
}

const RAW: readonly [string, string][] = [
  ['bit.ly', 'shortener_bitly'],
  ['tinyurl.com', 'shortener_tinyurl'],
  ['t.co', 'shortener_tco'],
  ['goo.gl', 'shortener_googl'],
  ['is.gd', 'shortener_isgd'],
  ['v.gd', 'shortener_vgd'],
  ['ow.ly', 'shortener_owly'],
  ['buff.ly', 'shortener_buffly'],
  ['adf.ly', 'shortener_adfly'],
  ['shorte.st', 'shortener_shortest'],
  ['cutt.ly', 'shortener_cuttly'],
  ['rebrand.ly', 'shortener_rebrandly'],
  ['shorturl.at', 'shortener_shorturlat'],
  ['rb.gy', 'shortener_rbgy'],
  ['tiny.cc', 'shortener_tinycc'],
  ['s.id', 'shortener_sid'],
  ['t.ly', 'shortener_tly'],
  ['lnkd.in', 'shortener_lnkd'],
  ['db.tt', 'shortener_dbtt'],
  ['qr.ae', 'shortener_qrae'],
  ['1url.com', 'shortener_1url'],
  ['trib.al', 'shortener_tribal'],
  ['clck.ru', 'shortener_clckru'],
  ['u.to', 'shortener_uto'],
  ['soo.gd', 'shortener_soogd'],
  ['ouo.io', 'shortener_ouoio'],
  ['mcaf.ee', 'shortener_mcafee'],
  ['shorturl.gg', 'shortener_shorturlgg'],
  ['v.gd', 'shortener_vgd'],
];

export const SHORTENERS: ReadonlyMap<string, ShortenerEntry> = new Map(
  RAW.map(([domain, nameKey]) => [domain, { domain, nameKey }]),
);

/** True when `domain` is a known shortener. */
export function isShortener(domain: string | null | undefined): boolean {
  if (!domain) return false;
  return SHORTENERS.has(domain.toLowerCase());
}

export function shortenerEntry(domain: string): ShortenerEntry | null {
  return SHORTENERS.get(domain.toLowerCase()) ?? null;
}
