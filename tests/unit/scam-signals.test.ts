/**
 * Page scam-signal validation.
 *
 * Content scripts observe hostile page content, so every payload is re-validated
 * before it can influence anything. These tests lock that boundary down.
 */
import { describe, expect, it } from 'vitest';
import { analyzePageSignals, sanitizeSignals, signalsToReasons } from '../../src/scam/signals';

const SENDER = { id: 'vbs', url: 'https://example.test/', origin: 'https://example.test' } as chrome.runtime.MessageSender;

describe('sanitizeSignals', () => {
  it('accepts a well-formed payload', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: [{ code: 'scam.fake_virus_alert', confidence: 'high', evidence: ['device-infected-claim'] }],
      formsAnalyzed: 2,
      linksAnalyzed: 40,
    });
    expect(result).not.toBeNull();
    expect(result!.signals).toHaveLength(1);
  });

  it('rejects a non-object payload', () => {
    for (const payload of [null, undefined, 'string', 42, true]) {
      expect(sanitizeSignals(payload)).toBeNull();
    }
  });

  it('rejects an over-long or missing url', () => {
    expect(sanitizeSignals({ url: '', signals: [] })).toBeNull();
    expect(sanitizeSignals({ url: 'x'.repeat(5000), signals: [] })).toBeNull();
    expect(sanitizeSignals({ signals: [] })).toBeNull();
  });

  it('drops unknown signal codes', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: [{ code: 'evil.inject', confidence: 'high', evidence: [] }],
    });
    expect(result!.signals).toHaveLength(0);
  });

  it('coerces an invalid confidence to low', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: [{ code: 'scam.fake_virus_alert', confidence: 'certain', evidence: [] }],
    });
    expect(result!.signals[0]!.confidence).toBe('low');
  });

  it('bounds the evidence list and each entry', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: [
        {
          code: 'scam.fake_virus_alert',
          confidence: 'high',
          evidence: Array.from({ length: 50 }, () => 'y'.repeat(1000)),
        },
      ],
    });
    expect(result!.signals[0]!.evidence.length).toBeLessThanOrEqual(8);
    for (const item of result!.signals[0]!.evidence) {
      expect(item.length).toBeLessThanOrEqual(120);
    }
  });

  it('caps the total number of signals', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: Array.from({ length: 100 }, () => ({ code: 'scam.fake_virus_alert', confidence: 'low', evidence: [] })),
    });
    expect(result!.signals.length).toBeLessThanOrEqual(8);
  });

  it('drops non-string evidence entries', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: [{ code: 'scam.fake_virus_alert', confidence: 'low', evidence: ['ok', 42, {}, null] }],
    });
    expect(result!.signals[0]!.evidence).toEqual(['ok']);
  });

  it('clamps implausible counters', () => {
    const result = sanitizeSignals({
      url: 'https://evil.test/',
      signals: [],
      formsAnalyzed: 10 ** 9,
      linksAnalyzed: -50,
    });
    expect(result!.formsAnalyzed).toBeLessThanOrEqual(1000);
    expect(result!.linksAnalyzed).toBeGreaterThanOrEqual(0);
  });
});

describe('analyzePageSignals', () => {
  it('degrades gracefully on a rejected payload', () => {
    const result = analyzePageSignals(null, SENDER);
    expect(result.signals).toHaveLength(0);
    expect(result.url).toBe('');
  });

  it('extracts the hostname defensively', () => {
    expect(analyzePageSignals({ url: 'https://evil.test/x', signals: [] }, SENDER).hostname).toBe('evil.test');
    expect(analyzePageSignals({ url: 'not-a-url', signals: [] }, SENDER).hostname).toBeNull();
  });
});

describe('signalsToReasons', () => {
  it('discounts a low-confidence signal', () => {
    const high = signalsToReasons([{ code: 'scam.fake_virus_alert', confidence: 'high', evidence: [] }]);
    const low = signalsToReasons([{ code: 'scam.fake_virus_alert', confidence: 'low', evidence: [] }]);
    expect(high[0]!.weight).toBeGreaterThan(low[0]!.weight);
  });

  it('maps every known signal to a reason code', () => {
    const reasons = signalsToReasons([
      { code: 'scam.fake_browser_update', confidence: 'high', evidence: [] },
      { code: 'scam.fake_virus_alert', confidence: 'high', evidence: [] },
      { code: 'scam.software_install_prompt', confidence: 'high', evidence: [] },
      { code: 'scam.credential_form', confidence: 'high', evidence: [] },
      { code: 'scam.lookalike_link_domain', confidence: 'high', evidence: [] },
    ]);
    expect(reasons).toHaveLength(5);
    for (const reason of reasons) expect(reason.code).toBeTruthy();
  });

  it('keeps page signals below the auto-block threshold', () => {
    // Every page signal combined must stay under the engine's SUSPICIOUS
    // threshold contribution from structure alone, so a page can never be
    // blocked purely on what it says about itself.
    const all = signalsToReasons([
      { code: 'scam.fake_browser_update', confidence: 'high', evidence: [] },
      { code: 'scam.fake_virus_alert', confidence: 'high', evidence: [] },
      { code: 'scam.software_install_prompt', confidence: 'high', evidence: [] },
      { code: 'scam.credential_form', confidence: 'high', evidence: [] },
      { code: 'scam.lookalike_link_domain', confidence: 'high', evidence: [] },
    ]);
    const total = all.reduce((sum, r) => sum + r.weight, 0);
    expect(total).toBeLessThan(200);
  });
});
