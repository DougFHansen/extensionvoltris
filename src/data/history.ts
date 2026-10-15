/**
 * Local security event history.
 *
 * Privacy constraints enforced here:
 *  - Only the registrable domain is stored by default. Full URLs require the user
 *    to explicitly enable `storeFullUrls`, and even then only the query string is
 *    stripped.
 *  - The list is a hard-capped ring buffer; old events are evicted.
 *  - Clearing history is instant and complete.
 */
import { HISTORY_MAX_ITEMS } from '../core/constants';
import type { HistoryEvent, HistoryKind, RiskReasonCode, RiskVerdict, ThreatCategory } from '../core/types';
import { get, set, K } from '../platform/storage';
import { normalizeHostname } from '../feeds/parsers';

let cached: HistoryEvent[] | null = null;
let seq = 0;

function isKind(v: unknown): v is HistoryKind {
  return (
    v === 'threat_blocked' ||
    v === 'suspicious_detected' ||
    v === 'tracker_blocked' ||
    v === 'ad_blocked' ||
    v === 'download_flagged' ||
    v === 'scam_signals' ||
    v === 'list_updated' ||
    v === 'list_error' ||
    v === 'allowlist_changed'
  );
}

function sanitize(raw: unknown): HistoryEvent[] {
  if (!Array.isArray(raw)) return [];
  const out: HistoryEvent[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const r = item as Record<string, unknown>;
    if (typeof r.id !== 'string' || typeof r.at !== 'number' || !isKind(r.kind)) continue;
    const domain = typeof r.domain === 'string' ? (normalizeHostname(r.domain) ?? '') : '';
    out.push({
      id: r.id.slice(0, 64),
      kind: r.kind,
      at: r.at,
      domain: domain.slice(0, 253),
      ...(typeof r.category === 'string' ? { category: r.category as ThreatCategory } : {}),
      ...(typeof r.verdict === 'string' ? { verdict: r.verdict as RiskVerdict } : {}),
      ...(typeof r.reasonCode === 'string' ? { reasonCode: r.reasonCode as RiskReasonCode } : {}),
      ...(typeof r.providerId === 'string' ? { providerId: r.providerId.slice(0, 64) } : {}),
      ...(typeof r.url === 'string' && r.url.length <= 2048 ? { url: r.url } : {}),
    });
    if (out.length >= HISTORY_MAX_ITEMS) break;
  }
  return out;
}

export async function getHistory(): Promise<HistoryEvent[]> {
  if (cached) return cached;
  const raw = await get<unknown>(K.history);
  cached = sanitize(raw);
  return cached;
}

export interface RecordHistoryInput {
  readonly kind: HistoryKind;
  readonly domain: string | null;
  readonly category?: ThreatCategory;
  readonly verdict?: RiskVerdict;
  readonly reasonCode?: RiskReasonCode;
  readonly providerId?: string;
  readonly url?: string;
  /** Honour the user's `storeFullUrls` preference. */
  readonly storeFullUrls: boolean;
}

/** Strips the query string and fragment before anything is persisted. */
function trimUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.search = '';
    parsed.hash = '';
    parsed.username = '';
    parsed.password = '';
    return parsed.toString().slice(0, 2048);
  } catch {
    return '';
  }
}

export async function recordHistory(input: RecordHistoryInput): Promise<void> {
  const list = await getHistory();
  seq += 1;
  const event: HistoryEvent = {
    id: `${Date.now().toString(36)}-${seq.toString(36)}`,
    kind: input.kind,
    at: Date.now(),
    domain: input.domain ? (normalizeHostname(input.domain) ?? '') : '',
    ...(input.category ? { category: input.category } : {}),
    ...(input.verdict ? { verdict: input.verdict } : {}),
    ...(input.reasonCode ? { reasonCode: input.reasonCode } : {}),
    ...(input.providerId ? { providerId: input.providerId } : {}),
    ...(input.storeFullUrls && input.url ? { url: trimUrl(input.url) } : {}),
  };

  const next = [event, ...list].slice(0, HISTORY_MAX_ITEMS);
  cached = next;
  await set(K.history, next);
}

export async function clearHistory(): Promise<void> {
  cached = [];
  await set(K.history, []);
}

export async function deleteHistoryEvent(id: string): Promise<void> {
  const list = await getHistory();
  const next = list.filter((e) => e.id !== id);
  if (next.length !== list.length) {
    cached = next;
    await set(K.history, next);
  }
}

/** Buckets used by the dashboard. */
export function summarize(history: readonly HistoryEvent[]): Record<HistoryKind, number> {
  const out: Record<string, number> = {};
  for (const event of history) out[event.kind] = (out[event.kind] ?? 0) + 1;
  return out as Record<HistoryKind, number>;
}

export function invalidateHistoryCache(): void {
  cached = null;
}
