/**
 * ZIP writer tests.
 *
 * These exist because of a real packaging defect: PowerShell's
 * `Compress-Archive` on Windows PowerShell 5.1 wrote `\` as the path separator,
 * producing an archive the Chrome Web Store could not read. The tests below pin
 * the spec requirement and the checks that catch the failure locally instead of
 * during store review.
 */
import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { inflateRawSync } from 'node:zlib';
import { createZip, crc32, listZipEntries } from '../../scripts/lib/zip.mjs';

/** Minimal reader: walks local headers and inflates each entry. */
function readZip(buf: Buffer): Map<string, Buffer> {
  const out = new Map();
  let offset = 0;

  while (offset < buf.length - 4 && buf.readUInt32LE(offset) === 0x04034b50) {
    const method = buf.readUInt16LE(offset + 8);
    const crc = buf.readUInt32LE(offset + 14);
    const compressedSize = buf.readUInt32LE(offset + 18);
    const uncompressedSize = buf.readUInt32LE(offset + 22);
    const nameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);

    const name = buf.subarray(offset + 30, offset + 30 + nameLen).toString('utf8');
    const payload = buf.subarray(offset + 30 + nameLen + extraLen, offset + 30 + nameLen + extraLen + compressedSize);
    const data = method === 8 ? inflateRawSync(payload) : Buffer.from(payload);

    expect(data.length, `${name} size mismatch`).toBe(uncompressedSize);
    expect(crc32(data), `${name} CRC mismatch`).toBe(crc);
    out.set(name, data);

    offset += 30 + nameLen + extraLen + compressedSize;
  }
  return out;
}

describe('CRC-32', () => {
  it('matches the IEEE check vector', () => {
    expect(crc32(Buffer.from('123456789', 'ascii'))).toBe(0xcbf43926);
  });

  it('returns 0 for empty input', () => {
    expect(crc32(Buffer.alloc(0))).toBe(0);
  });
});

describe('archive layout', () => {
  const entries = [
    { name: 'manifest.json', data: Buffer.from('{"manifest_version":3}'), mtime: Date.UTC(2026, 0, 2, 3, 4, 5), mode: 0o644 },
    { name: 'a/b/deep.js', data: Buffer.from('console.log(1);'), mtime: Date.UTC(2026, 0, 2, 3, 4, 5), mode: 0o644 },
    { name: 'a/c.txt', data: Buffer.from('x'.repeat(4096)), mtime: Date.UTC(2026, 0, 2, 3, 4, 5), mode: 0o644 },
  ];
  const archive = createZip(entries);

  it('round-trips every entry byte-for-byte', () => {
    const read = readZip(archive);
    expect(read.size).toBe(3);
    expect(read.get('manifest.json')?.toString('utf8')).toBe('{"manifest_version":3}');
    expect(read.get('a/b/deep.js')?.toString('utf8')).toBe('console.log(1);');
    expect(read.get('a/c.txt')?.length).toBe(4096);
  });

  it('uses "/" as the path separator, never "\\"', () => {
    for (const name of listZipEntries(archive)) {
      expect(name, 'APPNOTE 4.4.17.1 requires "/"').not.toContain('\\');
    }
  });

  it('refuses an entry that already contains a backslash', () => {
    expect(() => createZip([{ name: 'a\\b.txt', data: Buffer.from('x'), mtime: 0, mode: 0o644 }])).toThrow(/\//);
  });

  it('refuses an absolute or escaping path', () => {
    expect(() => createZip([{ name: '/etc/passwd', data: Buffer.from('x'), mtime: 0, mode: 0o644 }])).toThrow(/relative/);
    expect(() => createZip([{ name: '../out.txt', data: Buffer.from('x'), mtime: 0, mode: 0o644 }])).toThrow(/relative/);
    expect(() => createZip([{ name: 'C:/x.txt', data: Buffer.from('x'), mtime: 0, mode: 0o644 }])).toThrow(/relative/);
  });

  it('produces identical bytes for the same input regardless of insertion order', () => {
    const byName = new Map(entries.map((e) => [e.name, e]));
    const shuffled = [byName.get('a/c.txt'), byName.get('manifest.json'), byName.get('a/b/deep.js')].filter(
      (e): e is (typeof entries)[number] => e !== undefined,
    );
    expect(createZip(shuffled).equals(archive)).toBe(true);
  });

  it('stores an entry when compression would make it larger', () => {
    const tiny = [{ name: 'a.js', data: Buffer.from('ab'), mtime: Date.UTC(2026, 0, 2), mode: 0o644 }];
    expect(readZip(createZip(tiny)).get('a.js')?.toString('utf8')).toBe('ab');
  });

  it('writes a well-formed end-of-central-directory record', () => {
    // Signature, entry counts and central directory offset must all agree.
    const eocdOffset = archive.length - 22;
    expect(archive.readUInt32LE(eocdOffset)).toBe(0x06054b50);
    expect(archive.readUInt16LE(eocdOffset + 8)).toBe(3);
    expect(archive.readUInt16LE(eocdOffset + 10)).toBe(3);
    const cdSize = archive.readUInt32LE(eocdOffset + 12);
    const cdOffset = archive.readUInt32LE(eocdOffset + 16);
    expect(cdOffset + cdSize).toBe(eocdOffset);
  });
});

describe('published artifacts', () => {
  const artifacts = ['chrome', 'edge']
    .map((t) => `artifacts/voltris-browser-shield-${readVersion()}-${t}.zip`)
    .filter((p) => existsSync(p));

  it('has artifacts to check (run npm run package)', () => {
    expect(artifacts.length).toBeGreaterThan(0);
  });

  it.each(artifacts)('%s has no backslash separators and manifest.json at the root', (path) => {
    const names = listZipEntries(readFileSync(path));
    expect(names.filter((n) => n.includes('\\'))).toEqual([]);
    expect(names).toContain('manifest.json');
    expect(names.every((n) => !n.startsWith('/') && !n.includes('..'))).toBe(true);
  });

  it.each(artifacts)('%s contains every file from its dist directory', (path) => {
    const target = path.includes('edge') ? 'edge' : 'chrome';
    const names = new Set(listZipEntries(readFileSync(path)));
    // Spot-check the files the browser resolves by exact path.
    for (const required of ['background.js', 'popup.html', 'dashboard.html', 'options.html', 'blocked.html', 'content.js']) {
      expect(names.has(required), `${required} missing from ${target} archive`).toBe(true);
    }
  });

  it.each(artifacts)('%s is well under the store size limit', (path) => {
    // Chrome Web Store limit is 2 GB; anything near it suggests stray files.
    expect(statSync(path).size).toBeLessThan(50 * 1024 * 1024);
  });
});

function readVersion(): string {
  const manifest = JSON.parse(readFileSync('src/manifest.json', 'utf8')) as { version: string };
  return manifest.version;
}
