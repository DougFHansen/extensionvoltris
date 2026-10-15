/**
 * URL normalization and registrable-domain extraction.
 *
 * Uses reserved domains and RFC 2606 names only. No traffic leaves the machine.
 */
import { describe, expect, it } from 'vitest';
import { parseTarget, isIpv4Literal, toAsciiHost, hostMatchesDomain, labelsOf, longestSuffixMatch } from '../../src/security/url-normalize';
import { resolvePublicSuffix, setPslRootForTests } from '../../src/security/psl';
import { readFileSync } from 'node:fs';

interface PslFile {
  root: unknown;
}

/** Loads the real generated PSL so the tests exercise production data. */
function loadGeneratedPsl(): void {
  const raw = JSON.parse(readFileSync('src/generated/psl.json', 'utf8')) as PslFile;
  setPslRootForTests(raw.root as never, {
    source: 'test-fixture',
    license: 'MPL-2.0',
    sha256: 'a'.repeat(64),
    generatedAt: '2026-01-01',
    ruleCount: 10336,
  });
}

loadGeneratedPsl();

const resolve = resolvePublicSuffix;

describe('parseTarget - normal inputs', () => {
  it('parses a simple https URL', () => {
    const result = parseTarget('https://example.com/index.html', resolve);
    expect(result.normalized).toBe(true);
    expect(result.scheme).toBe('https');
    expect(result.hostname).toBe('example.com');
    expect(result.registrableDomain).toBe('example.com');
    expect(result.publicSuffix).toBe('com');
    expect(result.subdomain).toBeNull();
  });

  it('extracts the subdomain', () => {
    const result = parseTarget('https://a.b.example.com/x', resolve);
    expect(result.hostname).toBe('a.b.example.com');
    expect(result.registrableDomain).toBe('example.com');
    expect(result.subdomain).toBe('a.b');
  });

  it('accepts a bare hostname typed by a user', () => {
    const result = parseTarget('example.org', resolve);
    expect(result.hostname).toBe('example.org');
    expect(result.registrableDomain).toBe('example.org');
  });

  it('keeps a non-standard port', () => {
    const result = parseTarget('http://localhost:8080/path', resolve);
    expect(result.port).toBe('8080');
    expect(result.hostname).toBe('localhost');
  });

  it('lowercases the host', () => {
    expect(parseTarget('https://EXAMPLE.COM/', resolve).hostname).toBe('example.com');
  });

  it('strips a trailing dot from the host', () => {
    expect(parseTarget('https://example.com./', resolve).hostname).toBe('example.com');
  });
});

describe('parseTarget - registrable domain via the Public Suffix List', () => {
  it('handles multi-part public suffixes', () => {
    expect(parseTarget('https://shop.example.co.uk/', resolve).registrableDomain).toBe('example.co.uk');
    expect(parseTarget('https://a.b.example.com.br/', resolve).registrableDomain).toBe('example.com.br');
    expect(parseTarget('https://x.example.co.jp/', resolve).registrableDomain).toBe('example.co.jp');
  });

  it('treats a public suffix host as having no registrable domain', () => {
    const result = parseTarget('https://co.uk/', resolve);
    expect(result.publicSuffix).toBe('co.uk');
    expect(result.registrableDomain).toBe('');
  });

  it('handles wildcard public suffixes', () => {
    // *.ck is a wildcard rule in the PSL.
    const result = parseTarget('https://www.foo.ck/', resolve);
    expect(result.publicSuffix).toBe('foo.ck');
    expect(result.registrableDomain).toBe('www.foo.ck');
  });

  it('handles PSL exception rules', () => {
    // !www.ck means "ck" is the suffix for www.ck.
    const result = parseTarget('https://www.ck/', resolve);
    expect(result.publicSuffix).toBe('ck');
  });

  it('handles private-section suffixes used by shared hosting', () => {
    // github.io is in the PRIVATE section: the registrable domain is the user
    // sub-domain, not github.io itself.
    const result = parseTarget('https://attacker.github.io/', resolve);
    expect(result.registrableDomain).toBe('attacker.github.io');
  });
});

describe('parseTarget - hostile and malformed input', () => {
  it('rejects empty input', () => {
    expect(parseTarget('', resolve).error).toBe('empty');
    expect(parseTarget('   ', resolve).error).toBe('empty');
    expect(parseTarget(undefined, resolve).error).toBe('empty');
    expect(parseTarget(42, resolve).error).toBe('empty');
  });

  it('rejects over-long input', () => {
    expect(parseTarget(`https://example.com/${'a'.repeat(5000)}`, resolve).error).toBe('too_long');
  });

  it('rejects unsupported schemes', () => {
    expect(parseTarget('ftp://example.com/', resolve).error).toBe('unsupported_scheme');
    expect(parseTarget('javascript:alert(1)', resolve).error).toBe('unsupported_scheme');
    expect(parseTarget('data:text/html,<h1>x</h1>', resolve).error).toBe('unsupported_scheme');
    expect(parseTarget('chrome://settings', resolve).error).toBe('unsupported_scheme');
  });

  it('rejects a bare host that contains a path separator', () => {
    // "example.com/evil" must not be reinterpreted as the host "example.com".
    expect(parseTarget('example.com/evil', resolve).hostname).toBeNull();
  });

  it('removes control characters used to split a host', () => {
    const result = parseTarget('https://exa mple.com/', resolve);
    expect(result.hostname).toBe('example.com');
  });

  it('rejects hosts containing illegal characters', () => {
    // `new URL()` rejects `<` outright; other illegal characters survive
    // parsing and are caught by our own host validation. Both are refusals.
    for (const input of ['https://ex<ample>.com/', 'https://ex`ample.com/']) {
      const error = parseTarget(input, resolve).error;
      expect(['unparsable', 'invalid_host']).toContain(error);
    }
  });

  it('rejects PSL sentinel characters in the host', () => {
    // `*`, `!` and `$` are trie sentinels; a hostile hostname must not be able
    // to walk arbitrary branches of the trie.
    const result = parseTarget('https://com$/', resolve);
    expect(result.error).toBe('invalid_host');
  });

  it('never throws on adversarial input', () => {
    const inputs: unknown[] = [
      'https://',
      'https://.',
      'https://..',
      'https://%%%',
      '://nope',
      'https://xn--/',
      'https://[::1]/',
      { toString: () => 'https://example.com' },
      [],
      true,
    ];
    for (const input of inputs) {
      expect(() => parseTarget(input, resolve)).not.toThrow();
    }
  });
});

describe('ip literals', () => {
  it('detects valid IPv4 literals', () => {
    expect(isIpv4Literal('192.168.0.1')).toBe(true);
    expect(isIpv4Literal('8.8.8.8')).toBe(true);
  });

  it('rejects invalid IPv4 literals', () => {
    expect(isIpv4Literal('999.1.1.1')).toBe(false);
    expect(isIpv4Literal('01.1.1.1')).toBe(false);
    expect(isIpv4Literal('1.1.1')).toBe(false);
  });

  it('flags an IP-literal host and does not produce a registrable domain', () => {
    const result = parseTarget('http://203.0.113.10/', resolve);
    expect(result.isIpLiteral).toBe(true);
    expect(result.registrableDomain).toBeNull();
  });
});

describe('idna', () => {
  it('converts a unicode host to punycode', () => {
    const { ascii, hadUnicode } = toAsciiHost('b\u00fccher.example');
    expect(hadUnicode).toBe(true);
    expect(ascii.startsWith('xn--')).toBe(true);
  });

  it('leaves an ascii host untouched', () => {
    const { ascii, hadUnicode } = toAsciiHost('Example.COM');
    expect(ascii).toBe('example.com');
    expect(hadUnicode).toBe(false);
  });
});

describe('host helpers', () => {
  it('matches a host against a domain including subdomains', () => {
    expect(hostMatchesDomain('example.com', 'example.com')).toBe(true);
    expect(hostMatchesDomain('a.b.example.com', 'example.com')).toBe(true);
    expect(hostMatchesDomain('notexample.com', 'example.com')).toBe(false);
    expect(hostMatchesDomain('example.com.evil.tld', 'example.com')).toBe(false);
  });

  it('splits labels and drops empties', () => {
    expect(labelsOf('a..b.com')).toEqual(['a', 'b', 'com']);
  });

  it('finds the longest suffix match', () => {
    const brands = new Set(['paypal.com', 'paypal.com.br']);
    expect(longestSuffixMatch('login.paypal.com.br', brands)).toBe('paypal.com.br');
    expect(longestSuffixMatch('a.paypal.com.br.attacker.tld', brands)).toBeNull();
  });
});
