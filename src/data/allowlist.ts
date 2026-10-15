/**
 * Allowlist / blocklist persistence.
 *
 * Entries store only the registrable domain, never a path or query string, so
 * the allowlist can never become a browsing-history surrogate.
 */
import type { AllowlistEntry, AllowlistScope } from '../core/types';
import { get, set, K } from '../platform/storage';
import { resolvePublicSuffix } from '../security/psl';
import { normalizeHostname } from '../feeds/parsers';

const MAX_ENTRIES = 500;

let cached: AllowlistEntry[] | null = null;

function isValidScope(value: unknown): value is AllowlistScope {
  return value === 'all' || value === 'threats' || value === 'privacy';
}

function sanitize(raw: unknown): AllowlistEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: AllowlistEntry[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const record = item as Record<string, unknown>;
    const domain = typeof record.domain === 'string' ? normalizeHostname(record.domain) : null;
    if (!domain || seen.has(domain)) continue;
    if (!isValidScope(record.scope)) continue;
    seen.add(domain);
    out.push({
      domain,
      scope: record.scope,
      addedAt: typeof record.addedAt === 'number' && Number.isFinite(record.addedAt) ? record.addedAt : Date.now(),
      enabled: record.enabled !== false,
      ...(typeof record.addedFrom === 'string' && record.addedFrom.length <= 253
        ? { addedFrom: normalizeHostname(record.addedFrom) ?? undefined }
        : {}),
    });
    if (out.length >= MAX_ENTRIES) break;
  }
  return out;
}

export async function getAllowlist(): Promise<AllowlistEntry[]> {
  if (cached) return cached;
  const raw = await get<unknown>(K.allowlist);
  cached = sanitize(raw);
  return cached;
}

/** Normalizes any user input (URL or hostname) to a registrable domain. */
export function toAllowlistDomain(input: string): string | null {
  const host = normalizeHostname(input.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').split('/')[0] ?? '');
  if (!host) return null;
  const resolved = resolvePublicSuffix(host);
  if (resolved && resolved.domain.length > 0) return resolved.domain;
  return host;
}

export async function addToAllowlist(
  input: string,
  scope: AllowlistScope = 'threats',
  fromDomain?: string,
): Promise<AllowlistEntry | null> {
  const domain = toAllowlistDomain(input);
  if (!domain) return null;
  const list = await getAllowlist();
  const existing = list.find((e) => e.domain === domain);
  if (existing) {
    // Re-adding widens the scope; that is an explicit user action.
    if (existing.scope === scope) return existing;
    const updated: AllowlistEntry = { ...existing, scope, enabled: true };
    const next = list.map((e) => (e.domain === domain ? updated : e));
    await persist(next);
    return updated;
  }
  const entry: AllowlistEntry = {
    domain,
    scope,
    addedAt: Date.now(),
    enabled: true,
    ...(fromDomain ? { addedFrom: fromDomain } : {}),
  };
  await persist([...list, entry]);
  return entry;
}

export async function removeFromAllowlist(domain: string): Promise<boolean> {
  const normalized = normalizeHostname(domain.trim().toLowerCase());
  if (!normalized) return false;
  const list = await getAllowlist();
  const next = list.filter((e) => e.domain !== normalized);
  if (next.length === list.length) return false;
  await persist(next);
  return true;
}

export async function setEntryEnabled(domain: string, enabled: boolean): Promise<boolean> {
  const normalized = normalizeHostname(domain.trim().toLowerCase());
  if (!normalized) return false;
  const list = await getAllowlist();
  let changed = false;
  const next = list.map((e) => {
    if (e.domain !== normalized) return e;
    changed = true;
    return { ...e, enabled };
  });
  if (changed) await persist(next);
  return changed;
}

export async function setEntryScope(domain: string, scope: AllowlistScope): Promise<boolean> {
  const normalized = normalizeHostname(domain.trim().toLowerCase());
  if (!normalized) return false;
  const list = await getAllowlist();
  let changed = false;
  const next = list.map((e) => {
    if (e.domain !== normalized) return e;
    changed = true;
    return { ...e, scope };
  });
  if (changed) await persist(next);
  return changed;
}

export async function clearAllowlist(): Promise<void> {
  cached = [];
  await set(K.allowlist, []);
}

/** Fast membership test used by the analysis engine. */
export function allowlistDomainSet(entries: readonly AllowlistEntry[]): Set<string> {
  const out = new Set<string>();
  for (const entry of entries) {
    if (entry.enabled) out.add(entry.domain);
  }
  return out;
}

/** Scope-aware membership: used when deciding whether a block is overridden. */
export function isAllowed(entries: readonly AllowlistEntry[], domain: string): AllowlistEntry | null {
  return entries.find((e) => e.enabled && e.domain === domain) ?? null;
}

async function persist(next: AllowlistEntry[]): Promise<void> {
  cached = next;
  await set(K.allowlist, next);
}

export function invalidateAllowlistCache(): void {
  cached = null;
}
