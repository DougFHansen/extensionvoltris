/**
 * Interstitial driver.
 *
 * Why not a declarativeNetRequest `redirect` to our own page:
 *  - `redirect.extensionPath` resolves to a single fixed URL, so it cannot carry
 *    per-request data, and the only ways to inject data would be a regex rule
 *    (limited to 1000 rules) or reflecting the untrusted URL into the query
 *    string of a web-accessible page.
 *  - Our approach: the DNR rule blocks the navigation, `webNavigation`
 *    tells us exactly which URL was blocked and in which tab, and we then drive
 *    the tab to our own page with an OPAQUE TOKEN.
 *
 * Consequences, all of them security improvements:
 *  - `blocked.html` does NOT need to be web-accessible, so no web page can load
 *    or frame it.
 *  - The untrusted URL is never placed in a URL that another page could observe;
 *    it lives in `chrome.storage.session`, which is cleared when the browser
 *    closes and is not shared with content scripts.
 *  - The page re-runs the analysis itself through the service worker, so it
 *    trusts nothing that arrives in its own query string.
 */
import type { ThreatCategory } from '../core/types';
import { getSettings } from '../data/settings';
import { get, set } from '../platform/storage';

const SESSION_PREFIX = 'vbs.block.';
const RECORDS_KEY = 'vbs.block.records';
const MAX_RECORDS = 20;
/** Records older than this are treated as gone. */
const RECORD_TTL_MS = 5 * 60_000;

export interface BlockRecord {
  readonly id: string;
  readonly url: string;
  readonly tabId: number;
  readonly category: ThreatCategory;
  /** Feed that listed the destination. Not a rule id: no matched-rule feed exists. */
  readonly providerId: string;
  /** The exact dataset entry that matched, e.g. a parent domain. */
  readonly matchedDomain: string;
  readonly at: number;
}

let counter = 0;

function randomToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function readAll(): Promise<BlockRecord[]> {
  const raw = await get<BlockRecord[]>(RECORDS_KEY, 'session');
  if (!raw || !Array.isArray(raw)) return [];
  const now = Date.now();
  return raw.filter((r) => r && typeof r.id === 'string' && now - r.at < RECORD_TTL_MS);
}

async function writeAll(records: BlockRecord[]): Promise<void> {
  await set(RECORDS_KEY, records.slice(0, MAX_RECORDS), 'session');
}

export async function putBlockRecord(record: Omit<BlockRecord, 'id'>): Promise<string> {
  counter += 1;
  const id = `${randomToken()}${counter.toString(36)}`;
  const records = await readAll();
  records.push({ ...record, id });
  await writeAll(records);
  return id;
}

export async function getBlockRecord(id: string): Promise<BlockRecord | null> {
  if (!/^[0-9a-f]{32}[a-z0-9]{1,4}$/.test(id)) return null;
  const records = await readAll();
  return records.find((r) => r.id === id) ?? null;
}

export async function clearBlockRecords(): Promise<void> {
  await set(RECORDS_KEY, [], 'session');
}

/** Guards against a redirect loop when a rule fires repeatedly for one tab. */
const lastRedirectAt = new Map<number, number>();

/**
 * Replaces the browser's raw error page with our own explanation.
 *
 * Called from the production block observer for every top-level navigation we
 * verified one of our own rules blocked. This is a production path: it depends
 * only on `webNavigation`, never on the unpacked-only matched-rule feed.
 */
export async function handleMatchedNavigation(info: {
  url: string;
  tabId: number;
  category: ThreatCategory;
  providerId: string;
  matchedDomain: string;
}): Promise<void> {
  if (info.tabId < 0) return; // TAB_ID_NONE: not attached to a tab

  const now = Date.now();
  const previous = lastRedirectAt.get(info.tabId) ?? 0;
  if (now - previous < 2_000) return;
  lastRedirectAt.set(info.tabId, now);
  if (lastRedirectAt.size > 200) lastRedirectAt.clear();

  const settings = await getSettings();
  if (!settings.protectionEnabled) return;

  const id = await putBlockRecord({
    url: info.url,
    tabId: info.tabId,
    category: info.category,
    providerId: info.providerId,
    matchedDomain: info.matchedDomain,
    at: now,
  });

  try {
    await chrome.tabs.update(info.tabId, { url: chrome.runtime.getURL(`blocked.html?id=${id}`) });
  } catch {
    // The tab may have been closed or navigated away between the block and the
    // redirect. Nothing to do: the user already left.
  }
}
