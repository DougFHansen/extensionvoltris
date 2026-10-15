/**
 * Minimal, dependency-free ZIP writer.
 *
 * WHY THIS EXISTS
 * ---------------
 * The first packaging implementation shelled out to PowerShell's
 * `Compress-Archive`, which on Windows PowerShell 5.1 writes `\` as the path
 * separator inside the archive. The ZIP specification (APPNOTE 4.4.17.1) requires
 * `/`. An extension package with backslash entries is misparsed by the Chrome Web
 * Store upload and by some unzip implementations, so the package would have been
 * rejected at submission time.
 *
 * Writing the archive here removes the OS compressor from the critical path and
 * makes the output byte-identical across platforms.
 *
 * Only what an extension package needs is implemented: deflate or store, no
 * ZIP64, no directory entries, no encryption. Files are emitted flat and sorted,
 * so the same input always produces the same bytes.
 */
import { deflateRawSync } from 'node:zlib';

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL = 0x06054b50;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

/** Unix permissions -> MS-DOS attribute byte. */
function dosAttributes(mode) {
  // 0x10 = directory, 0x20 = archive. Only regular files are emitted here.
  return (mode & 0o111 ? 0x01 : 0) | 0x20;
}

/** Converts an epoch milliseconds value to the MS-DOS date/time pair. */
function dosDateTime(epochMs) {
  const d = new Date(epochMs);
  const year = Math.max(1980, d.getFullYear());
  // Seconds have 2-second granularity in the DOS format.
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time: time & 0xffff, date: date & 0xffff };
}

/**
 * Builds a ZIP archive.
 *
 * @param {{name: string, data: Buffer, mtime: number, mode: number}[]} entries
 *        Paths must use `/` as the separator.
 * @returns {Buffer}
 */
export function createZip(entries) {
  // Deterministic ordering: byte-wise sort of the path.
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const entry of sorted) {
    if (entry.name.includes('\\')) {
      throw new Error(`zip entry must use "/" separators: ${JSON.stringify(entry.name)}`);
    }
    if (entry.name.startsWith('/') || /^[A-Za-z]:/.test(entry.name) || entry.name.split('/').includes('..')) {
      throw new Error(`zip entry must be a relative path without "..": ${entry.name}`);
    }

    const nameBuf = Buffer.from(entry.name, 'utf8');
    const crc = crc32(entry.data);
    const { time, date } = dosDateTime(entry.mtime);
    // Try compression, and fall back to storing when it would grow the entry.
    // A tiny file can deflate to something larger than its source.
    const deflated = deflateRawSync(entry.data, { level: 9 });
    const useDeflate = deflated.length < entry.data.length;
    const payload = useDeflate ? deflated : entry.data;
    const method = useDeflate ? METHOD_DEFLATE : METHOD_STORE;

    const local = Buffer.alloc(30 + nameBuf.length);
    local.writeUInt32LE(LOCAL_HEADER, 0);
    local.writeUInt16LE(20, 4); // version needed to extract: 2.0 (deflate)
    local.writeUInt16LE(0, 6); // general purpose flags
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    nameBuf.copy(local, 30);

    locals.push(local, payload);

    const central = Buffer.alloc(46 + nameBuf.length);
    central.writeUInt32LE(CENTRAL_HEADER, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(payload.length, 20);
    central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk number start
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE(dosAttributes(entry.mode), 38);
    central.writeUInt32LE(offset, 42);
    nameBuf.copy(central, 46);

    centrals.push(central);
    offset += local.length + payload.length;
  }

  const centralBuf = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(END_OF_CENTRAL, 0);
  end.writeUInt16LE(0, 4); // this disk
  end.writeUInt16LE(0, 6); // disk with central directory
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...locals, centralBuf, end]);
}

let CRC_TABLE = null;

/** CRC-32 (IEEE 802.3), the checksum ZIP requires. */
export function crc32(buf) {
  if (CRC_TABLE === null) {
    CRC_TABLE = new Int32Array(256);
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c;
    }
  }
  let crc = -1;
  for (let i = 0; i < buf.length; i += 1) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buf[i]) & 0xff];
  return (crc ^ -1) >>> 0;
}

/**
 * Reads back every entry name stored in an archive.
 *
 * Used by the packaging verification step so a regression that reintroduces
 * backslash separators fails the build instead of failing at store submission,
 * where the error message says nothing useful.
 */
export function listZipEntries(buf) {
  const names = [];
  let offset = 0;

  while (offset < buf.length - 4 && buf.readUInt32LE(offset) === LOCAL_HEADER) {
    const compressedSize = buf.readUInt32LE(offset + 18);
    const nameLen = buf.readUInt16LE(offset + 26);
    const extraLen = buf.readUInt16LE(offset + 28);
    names.push(buf.subarray(offset + 30, offset + 30 + nameLen).toString('utf8'));
    offset += 30 + nameLen + extraLen + compressedSize;
  }
  return names;
}
