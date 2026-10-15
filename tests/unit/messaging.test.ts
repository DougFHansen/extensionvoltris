/**
 * Message protocol validation - the trust boundary between the popup, the
 * dashboard, content scripts and the service worker.
 */
import { describe, expect, it } from 'vitest';
import { PROTOCOL_VERSION, parseEnvelope, validatePayload, envelope, ok, err } from '../../src/platform/messages';

describe('envelope parsing', () => {
  it('accepts a well-formed envelope', () => {
    const parsed = parseEnvelope({ v: PROTOCOL_VERSION, t: 'get.status', p: {} });
    expect(parsed).not.toBeNull();
    expect(parsed!.t).toBe('get.status');
  });

  it('rejects a wrong protocol version', () => {
    expect(parseEnvelope({ v: 99, t: 'get.status' })).toBeNull();
    expect(parseEnvelope({ t: 'get.status' })).toBeNull();
  });

  it('rejects an unknown message type', () => {
    expect(parseEnvelope({ v: PROTOCOL_VERSION, t: 'system.eval' })).toBeNull();
    expect(parseEnvelope({ v: PROTOCOL_VERSION, t: '__proto__' })).toBeNull();
    expect(parseEnvelope({ v: PROTOCOL_VERSION, t: 'constructor' })).toBeNull();
  });

  it('rejects non-object payloads', () => {
    for (const raw of [null, undefined, 'string', 42, [], true]) {
      expect(parseEnvelope(raw)).toBeNull();
    }
  });

  it('bounds the correlation id', () => {
    const parsed = parseEnvelope({ v: PROTOCOL_VERSION, t: 'get.status', id: 'x'.repeat(500) });
    expect(parsed!.id).toBeUndefined();
  });

  it('round-trips through the envelope helper', () => {
    const message = envelope('allowlist.add', { domain: 'a.test', scope: 'privacy' }, 'id-1');
    expect(parseEnvelope(message)).not.toBeNull();
  });
});

describe('payload validation', () => {
  it('accepts a payload-less request', () => {
    // `envelope()` omits `p` entirely when there is nothing to send, so every
    // no-argument message type must validate against an absent payload.
    for (const type of ['get.status', 'settings.get', 'get.dashboard', 'history.list', 'allowlist.list', 'feeds.state', 'rules.diagnostics', 'download.lists'] as const) {
      expect(validatePayload(type, undefined), type).toEqual({});
      expect(validatePayload(type, {}), type).toEqual({});
    }
  });

  it('accepts a valid analysis request', () => {
    expect(validatePayload('get.analysis', { url: 'https://example.test/' })).toEqual({ url: 'https://example.test/' });
  });

  it('rejects an over-long URL', () => {
    expect(validatePayload('get.analysis', { url: 'x'.repeat(200_000) })).toBeNull();
    expect(validatePayload('get.analysis', { url: '' })).toBeNull();
  });

  it('rejects a non-object payload for object-only types', () => {
    expect(validatePayload('get.status', 'string')).toBeNull();
    expect(validatePayload('get.status', [])).toBeNull();
    expect(validatePayload('get.status', null)).toBeNull();
  });

  it('validates the allowlist scope', () => {
    expect(validatePayload('allowlist.add', { domain: 'a.test', scope: 'all' })).not.toBeNull();
    expect(validatePayload('allowlist.add', { domain: 'a.test', scope: 'evil' })).toBeNull();
    expect(validatePayload('allowlist.add', { domain: 'a.test' })).toBeNull();
    expect(validatePayload('allowlist.add', { domain: '', scope: 'all' })).toBeNull();
  });

  it('sanitises the settings patch', () => {
    const patch = validatePayload('settings.patch', {
      blockAds: true,
      updateIntervalHours: 12,
      theme: 'dark',
      evil: 'x',
      fn: () => undefined,
      sym: Symbol('x'),
    }) as Record<string, unknown>;
    expect(patch.blockAds).toBe(true);
    expect(patch.updateIntervalHours).toBe(12);
    expect(patch.theme).toBe('dark');
    // Unknown keys and non-primitive values are dropped.
    expect(patch.evil).toBeUndefined();
    expect(patch.fn).toBeUndefined();
    expect(patch.sym).toBeUndefined();
  });

  it('caps the number of settings keys in one patch', () => {
    const huge: Record<string, unknown> = {};
    for (let i = 0; i < 200; i += 1) huge[`k${i}`] = true;
    const patch = validatePayload('settings.patch', huge) as Record<string, unknown>;
    expect(Object.keys(patch).length).toBeLessThanOrEqual(32);
  });

  it('rejects a prototype-polluting settings patch', () => {
    const patch = validatePayload('settings.patch', JSON.parse('{"__proto__":{"polluted":true},"constructor":{"x":1}}'));
    expect(patch).not.toHaveProperty('__proto__.polluted');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('validates the interstitial token', () => {
    // Tokens are 32 hex characters plus a short base36 counter suffix.
    const valid = `${'a'.repeat(32)}1`;
    expect(validatePayload('blocked.details', { token: valid })).toEqual({ token: valid });
    expect(validatePayload('blocked.details', { token: 'short' })).toBeNull();
    expect(validatePayload('blocked.details', { token: 'A'.repeat(32) })).toBeNull();
    expect(validatePayload('blocked.details', { token: `${'a'.repeat(32)}!!!!` })).toBeNull();
    expect(validatePayload('blocked.details', { token: 123 })).toBeNull();
  });

  it('validates the tab id for a rescan', () => {
    expect(validatePayload('page.rescan', { tabId: 5 })).toEqual({ tabId: 5 });
    expect(validatePayload('page.rescan', { tabId: -1 })).toBeNull();
    expect(validatePayload('page.rescan', { tabId: 1.5 })).toBeNull();
    expect(validatePayload('page.rescan', { tabId: '5' })).toBeNull();
  });

  it('bounds a content-script signal list', () => {
    const signals = Array.from({ length: 500 }, () => ({ code: 'scam.fake_virus_alert', confidence: 'low', evidence: [] }));
    expect(validatePayload('content.scamSignals', { url: 'https://x.test/', signals })).toBeNull();
  });

  it('rejects an unknown message type outright', () => {
    expect(validatePayload('does.not.exist' as never, {})).toBeNull();
  });
});

describe('response helpers', () => {
  it('builds success and failure envelopes', () => {
    expect(ok({ a: 1 })).toEqual({ ok: true, data: { a: 1 } });
    expect(err('boom', 'error_generic', 'id-1')).toEqual({
      ok: false,
      error: 'boom',
      messageKey: 'error_generic',
      id: 'id-1',
    });
  });
});
