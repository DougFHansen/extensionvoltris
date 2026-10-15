/**
 * Internal messaging protocol.
 *
 * Security model (Section 14 of the specification):
 *  - Every message carries a `v` protocol tag and a `t` type tag.
 *  - Payloads are validated by an explicit whitelist before any code runs on
 *    them. A message that does not match is rejected, logged and ignored.
 *  - Content scripts are treated as UNTRUSTED. They run in an isolated world but
 *    they observe hostile page content, so nothing they send is trusted.
 *  - There is no `externally_connectable`, so no web page can reach this API.
 */



import { DEFAULT_SETTINGS } from '../core/types';

export const PROTOCOL_VERSION = 1;

export type MessageType =
  // UI -> background
  | 'get.status'
  | 'get.analysis'
  | 'get.dashboard'
  | 'settings.get'
  | 'settings.patch'
  | 'settings.reset'
  | 'allowlist.list'
  | 'allowlist.add'
  | 'allowlist.remove'
  | 'allowlist.toggle'
  | 'allowlist.scope'
  | 'history.list'
  | 'history.clear'
  | 'history.delete'
  | 'feeds.refresh'
  | 'feeds.state'
  | 'feeds.credential'
  | 'rules.diagnostics'
  | 'data.clear'
  | 'data.usage'
  | 'page.rescan'
  | 'download.lists'
  | 'blocked.details'
  // content -> background
  | 'content.scamSignals'
  | 'content.linkInspect'
  // background -> content
  | 'content.hoverResult';

export interface Envelope<T = unknown> {
  /** Protocol tag. */
  readonly v: number;
  /** Message type. */
  readonly t: MessageType;
  /** Correlation id for request/response pairing. */
  readonly id?: string;
  /** Optional payload. */
  readonly p?: T;
}

export interface ResponseOk<T = unknown> {
  readonly ok: true;
  readonly id?: string;
  readonly data: T;
}

export interface ResponseErr {
  readonly ok: false;
  readonly id?: string;
  readonly error: string;
  /** i18n key describing the failure for the UI. */
  readonly messageKey: string;
}

export type Response<T = unknown> = ResponseOk<T> | ResponseErr;

export function envelope<T>(t: MessageType, p?: T, id?: string): Envelope<T> {
  return p === undefined ? { v: PROTOCOL_VERSION, t, ...(id ? { id } : {}) } : { v: PROTOCOL_VERSION, t, p, ...(id ? { id } : {}) };
}

export function ok<T>(data: T, id?: string): ResponseOk<T> {
  return id === undefined ? { ok: true, data } : { ok: true, data, id };
}

export function err(message: string, messageKey = 'error_generic', id?: string): ResponseErr {
  return id === undefined ? { ok: false, error: message, messageKey } : { ok: false, error: message, messageKey, id };
}

/** Upper bound for any inbound string field. */
const MAX_STRING = 8192;

/**
 * Runtime validation for message payloads.
 *
 * `envelope()` omits `p` entirely when the caller has nothing to send, so an
 * absent payload is normalized to `{}` before validation. Without this, every
 * request that legitimately carries no data (`get.status`, `settings.get`, ...)
 * would be rejected by its own type guard.
 *
 * Returns the narrowed payload, or null when validation fails.
 */
export function validatePayload(t: MessageType, p: unknown): unknown | null {
  const payload = p === undefined ? {} : p;

  switch (t) {
    case 'get.status':
    case 'settings.get':
    case 'settings.reset':
    case 'history.clear':
    case 'feeds.refresh':
    case 'data.clear':
      return isPlainObject(payload) ? payload : null;

    case 'get.analysis': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.url, MAX_STRING) ? { url: source.url } : null;
    }

    case 'get.dashboard':
    case 'feeds.state':
    case 'rules.diagnostics':
    case 'data.usage':
    case 'download.lists':
    case 'history.list':
    case 'allowlist.list':
      return isPlainObject(payload) ? payload : null;

    case 'settings.patch':
      return isPlainObject(payload) ? sanitizeSettingsPatch(payload) : null;

    case 'allowlist.add': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.domain, MAX_STRING) && isScope(source.scope)
        ? { domain: source.domain, scope: source.scope, ...(isBoundedString(source.from, 253) ? { from: source.from } : {}) }
        : null;
    }

    case 'allowlist.remove': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.domain, MAX_STRING) ? { domain: source.domain } : null;
    }

    case 'allowlist.toggle': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.domain, MAX_STRING) && (source.enabled === undefined || typeof source.enabled === 'boolean')
        ? { domain: source.domain, enabled: source.enabled }
        : null;
    }

    case 'allowlist.scope': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.domain, MAX_STRING) && isScope(source.scope)
        ? { domain: source.domain, scope: source.scope }
        : null;
    }

    case 'history.delete': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.id, 64) ? { id: source.id } : null;
    }

    case 'feeds.credential': {
      const source = isPlainObject(payload) ? payload : {};
      // Credentials are accepted but never echoed back and never logged.
      return isBoundedString(source.providerId, 64) && typeof source.key === 'string' && source.key.length <= 512
        ? { providerId: source.providerId, key: source.key }
        : null;
    }

    case 'page.rescan': {
      const source = isPlainObject(payload) ? payload : {};
      return typeof source.tabId === 'number' && Number.isInteger(source.tabId) && source.tabId >= 0
        ? { tabId: source.tabId }
        : null;
    }

    case 'blocked.details': {
      const source = isPlainObject(payload) ? payload : {};
      // The token format is validated HERE, not only at lookup time, so a
      // malformed token never reaches the storage layer.
      return typeof source.token === 'string' && TOKEN_RE.test(source.token) ? { token: source.token } : null;
    }

    case 'content.scamSignals':
      return isPlainObject(payload) && Array.isArray(payload.signals) && payload.signals.length <= 64 ? payload : null;

    case 'content.linkInspect': {
      const source = isPlainObject(payload) ? payload : {};
      return isBoundedString(source.url, MAX_STRING) ? { url: source.url } : null;
    }

    default:
      return null;
  }
}

/** Every settings key the protocol accepts, derived from the shipped defaults. */
const SETTINGS_KEYS: ReadonlySet<string> = new Set(Object.keys(DEFAULT_SETTINGS));

/**
 * Restricts a settings patch to known keys with primitive values.
 *
 * Dropping unknown keys HERE (not only when applying them) means a compromised
 * or buggy caller cannot smuggle arbitrary keys through the message boundary.
 */
function sanitizeSettingsPatch(p: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let count = 0;
  for (const [key, value] of Object.entries(p)) {
    if (count >= 32) break;
    if (key === 'version' || !SETTINGS_KEYS.has(key)) continue;
    if (value === null || value === undefined) continue;
    if (typeof value === 'boolean') {
      out[key] = value;
      count += 1;
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      out[key] = value;
      count += 1;
    } else if (typeof value === 'string' && value.length <= 64) {
      out[key] = value;
      count += 1;
    }
  }
  return out;
}

/** Opaque interstitial token: 32 hex characters plus a short base36 suffix. */
const TOKEN_RE = /^[0-9a-f]{32}[a-z0-9]{1,4}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isBoundedString(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max;
}

function isScope(value: unknown): boolean {
  return value === 'all' || value === 'threats' || value === 'privacy';
}

/** Parses an inbound message, returning null when it is malformed. */
export function parseEnvelope(raw: unknown): Envelope | null {
  if (!isPlainObject(raw)) return null;
  if (raw.v !== PROTOCOL_VERSION) return null;
  if (typeof raw.t !== 'string') return null;
  if (!isKnownType(raw.t)) return null;
  const id = raw.id === undefined ? undefined : isBoundedString(raw.id, 64) ? raw.id : undefined;
  return {
    v: PROTOCOL_VERSION,
    t: raw.t,
    ...(id ? { id } : {}),
    ...(raw.p === undefined ? {} : { p: raw.p }),
  };
}

const KNOWN_TYPES = new Set<MessageType>([
  'get.status', 'get.analysis', 'get.dashboard', 'settings.get', 'settings.patch', 'settings.reset',
  'allowlist.list', 'allowlist.add', 'allowlist.remove', 'allowlist.toggle', 'allowlist.scope',
  'history.list', 'history.clear', 'history.delete', 'feeds.refresh', 'feeds.state', 'feeds.credential',
  'rules.diagnostics', 'data.clear', 'data.usage', 'page.rescan', 'download.lists', 'blocked.details',
  'content.scamSignals', 'content.linkInspect', 'content.hoverResult',
]);

function isKnownType(value: string): value is MessageType {
  return KNOWN_TYPES.has(value as MessageType);
}

/** Sends a request and resolves with the validated response envelope. */
export async function request<T>(t: MessageType, p?: unknown): Promise<Response<T>> {
  const id = `${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
  const message = envelope(t, p, id);
  try {
    const response = (await chrome.runtime.sendMessage(message)) as Response<T> | undefined;
    if (!response || typeof response !== 'object') return err('no_response', 'error_no_response');
    if (response.ok !== true) {
      return { ok: false, error: 'remote_error', messageKey: 'error_generic', id };
    }
    return response as ResponseOk<T>;
  } catch {
    return err('disconnected', 'error_service_worker');
  }
}
