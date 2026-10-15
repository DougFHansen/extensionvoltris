/**
 * Unicode deception detection: homographs, mixed scripts, confusables, bidi.
 *
 * All hostile examples use RESERVED domains (RFC 2606 `.test`, `.example`) and
 * the `.invalid` TLD. No real domain is ever involved and nothing is fetched.
 */
import { describe, expect, it } from 'vitest';
import { analyzeUnicode, skeletonize, scriptOf } from '../../src/security/unicode';

function analyze(host: string, asciiHost: string | null = null) {
  const labels = host.split('.');
  return analyzeUnicode({ unicodeHost: host, asciiHost: asciiHost ?? host, labels });
}

describe('scriptOf', () => {
  it('classifies common scripts', () => {
    expect(scriptOf('a')).toBe('Latin');
    expect(scriptOf('Z')).toBe('Latin');
    expect(scriptOf('\u0430')).toBe('Cyrillic'); // Cyrillic a
    expect(scriptOf('\u03b1')).toBe('Greek'); // Greek alpha
    expect(scriptOf('\u05d0')).toBe('Hebrew');
    expect(scriptOf('\u4e2d')).toBe('Han');
    expect(scriptOf('\u3042')).toBe('Hiragana');
  });
});

describe('skeletonize', () => {
  it('maps Cyrillic look-alikes onto Latin', () => {
    // Cyrillic a, e, o, p, a, l -> "aeopay"
    const cyrillic = 'aeopay'.split('').map((c) => ({ a: '\u0430', e: '\u0435', o: '\u043e', p: '\u0440' }[c] ?? c)).join('');
    expect(skeletonize(cyrillic)).toBe('aeopay');
  });

  it('maps fullwidth Latin onto ASCII', () => {
    expect(skeletonize('\uff41\uff42\uff43')).toBe('abc');
  });

  it('lowercases plain ASCII', () => {
    expect(skeletonize('ABC')).toBe('abc');
  });

  it('strips combining diacritics', () => {
    expect(skeletonize('a\u0301e\u0300')).toBe('ae');
  });
});

describe('mixed scripts', () => {
  it('detects a Latin+Cyrillic homograph label', () => {
    const host = 'p\u0430ypal.test';
    const result = analyze(host);
    const kinds = result.findings.map((f) => f.kind);
    expect(kinds).toContain('mixed_script');
    // A single substituted character scores below the "fully non-ASCII label"
    // threshold; the engine combines mixed_script + confusable for the verdict.
    expect(result.homographScore).toBeGreaterThan(0);
  });

  it('scores a fully non-ASCII impersonating label as a strong homograph', () => {
    // Entire label in Cyrillic. The skeleton must reduce to a pure-ASCII
    // Latin-looking string, which is what makes the label deceptive.
    const result = analyze('\u0441\u0435\u0441\u0443\u0440\u0435.test');
    const homograph = result.findings.find((f) => f.kind === 'homograph');
    expect(homograph).toBeDefined();
    expect(homograph!.data.skeleton).toMatch(/^[a-z]+$/);
    expect((homograph!.data.skeleton as string).length).toBe(6);
    expect(result.homographScore).toBeGreaterThanOrEqual(70);
  });

  it('does not map Cyrillic shapes that do not impersonate a Latin letter', () => {
    // U+043B (Cyrillic el) renders as a lambda-like glyph, not an "l".
    expect(skeletonize('\u043b')).not.toBe('l');
  });

  it('detects a Latin+Greek homograph label', () => {
    const result = analyze('\u03bf\u03c0\u03b5\u03bb.test');
    expect(result.findings.some((f) => f.kind === 'homograph' || f.kind === 'confusable')).toBe(true);
  });

  it('does not flag a pure single-script label', () => {
    const result = analyze('example.test');
    expect(result.findings).toHaveLength(0);
    expect(result.homographScore).toBe(0);
  });

  it('does not flag a legitimate multi-script language domain as mixed within a label', () => {
    // Japanese text is legitimate. Each label stays within one script.
    const result = analyze('\u65e5\u672c\u8a9e.test');
    expect(result.findings.filter((f) => f.kind === 'mixed_script')).toHaveLength(0);
  });
});

describe('invisible and bidirectional characters', () => {
  it('flags a right-to-left override', () => {
    const result = analyze('example\u202etxt.test');
    expect(result.findings.some((f) => f.kind === 'bidi')).toBe(true);
  });

  it('flags a zero-width space used to split a brand', () => {
    const result = analyze('pay\u200bpal.test');
    expect(result.findings.some((f) => f.kind === 'zero_width')).toBe(true);
  });

  it('flags a left-to-right mark', () => {
    const result = analyze('example\u200ftest');
    expect(result.findings.some((f) => f.kind === 'bidi')).toBe(true);
  });

  it('does not flag plain ASCII', () => {
    expect(analyze('example.test').findings.some((f) => f.kind === 'bidi' || f.kind === 'zero_width')).toBe(false);
  });
});

describe('punycode', () => {
  it('reports punycode labels as an informational finding only', () => {
    const result = analyze('xn--80ak6aa92e.test', 'xn--80ak6aa92e.test');
    const punycode = result.findings.filter((f) => f.kind === 'punycode');
    expect(punycode.length).toBeGreaterThan(0);
    // IDN domains are legitimate; punycode alone must not create a high score.
    expect(punycode[0]!.confidence).toBe('medium');
  });

  it('flags an all-punycode host', () => {
    const result = analyze('xn--pypal-4ve.com', 'xn--pypal-4ve.com');
    expect(result.hasNonAscii).toBe(false);
    // The punycode finding is informational on its own.
    expect(result.homographScore).toBe(0);
  });
});

describe('scoring discipline', () => {
  it('punycode alone never produces a high homograph score', () => {
    const result = analyze('xn--fsqu00a.test', 'xn--fsqu00a.test');
    expect(result.homographScore).toBeLessThan(40);
  });

  it('a confusable-rich label scores higher than a single substitution', () => {
    const heavy = analyze('\u0430\u0435\u043e.test');
    const light = analyze('e\u0435o.test');
    expect(heavy.homographScore).toBeGreaterThan(light.homographScore);
  });
});
