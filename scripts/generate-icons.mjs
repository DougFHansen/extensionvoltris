#!/usr/bin/env node
/**
 * Generates the extension icons as real PNG files.
 *
 * No image dependencies: the PNG encoder (CRC32 + zlib deflate) is implemented
 * here so the build stays dependency-free and reproducible.
 *
 * The mark is a VOLTRIS shield: a rounded shield silhouette with a check,
 * rendered with anti-aliased coverage by supersampling 4x4.
 */
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = resolve(HERE, '..', 'src', 'assets', 'icons');
const SIZES = [16, 32, 48, 128];
const SS = 4; // supersampling factor

// ---------------------------------------------------------------- PNG codec

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([length, body, crc]);
}

/** Encodes RGBA pixel data as a PNG buffer. */
function encodePng(width, height, rgba) {
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (width * 4 + 1);
    raw[rowStart] = 0; // filter type: none
    rgba.copy(raw, rowStart + 1, y * width * 4, (y + 1) * width * 4);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ------------------------------------------------------------------ drawing

const BRAND_TOP = [15, 155, 142];
const BRAND_BOTTOM = [11, 122, 112];
const CHECK = [255, 255, 255];

/** Signed distance to a shield outline, normalised to the icon box. */
function shieldCoverage(x, y) {
  // Shield path in a 0..1 box: flat top with rounded corners, vertical
  // shoulders, then a curve converging to a point at the base.
  const cx = 0.5;
  const top = 0.12;
  const bottom = 0.94;
  const halfWidth = 0.33;
  const shoulder = 0.40; // fraction of the height where the taper begins

  const ny = (y - top) / (bottom - top);
  if (ny < 0 || ny > 1) return 0;

  let width;
  if (ny < shoulder) {
    width = halfWidth;
  } else {
    const k = (ny - shoulder) / (1 - shoulder);
    // Super-ellipse with exponent > 2 produces a V-shaped taper: pointed, not round.
    width = halfWidth * Math.pow(Math.max(0, 1 - Math.pow(k, 2.4)), 0.62);
  }
  const dx = Math.abs(x - cx) / width;
  if (dx > 1) return 0;

  // Slightly chamfered top corners (a shield has a flat top, not a dome).
  const capHeight = 0.055;
  if (ny < capHeight) {
    const k = ny / capHeight;
    const limit = halfWidth * (0.82 + 0.18 * k);
    if (Math.abs(x - cx) > limit) return 0;
  }

  // Feather the edge for anti-aliasing at the supersampled scale.
  return Math.max(0, Math.min(1, (1 - dx) * width * 90));
}

/** Coverage of the check mark glyph, in the 0..1 box. */
function checkCoverage(x, y) {
  const segments = [
    [0.35, 0.53, 0.45, 0.645],
    [0.45, 0.645, 0.66, 0.4],
  ];
  const thickness = 0.062;
  for (const [x1, y1, x2, y2] of segments) {
    const d = distanceToSegment(x, y, x1, y1, x2, y2);
    if (d < thickness) return Math.max(0, Math.min(1, (thickness - d) / thickness + 0.5));
  }
  return 0;
}

function distanceToSegment(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSquared = dx * dx + dy * dy;
  let t = lengthSquared === 0 ? 0 : ((px - x1) * dx + (py - y1) * dy) / lengthSquared;
  t = Math.max(0, Math.min(1, t));
  const cx = x1 + t * dx;
  const cy = y1 + t * dy;
  return Math.hypot(px - cx, py - cy);
}

function blend(dst, offset, r, g, b, alpha) {
  const inv = 1 - alpha;
  dst[offset] = Math.round(r * alpha + dst[offset] * inv);
  dst[offset + 1] = Math.round(g * alpha + dst[offset + 1] * inv);
  dst[offset + 2] = Math.round(b * alpha + dst[offset + 2] * inv);
  dst[offset + 3] = Math.round(255 * alpha + dst[offset + 3] * inv);
}

function renderIcon(size) {
  const pixels = Buffer.alloc(size * size * 4);
  const step = 1 / (size * SS);

  for (let py = 0; py < size; py += 1) {
    for (let px = 0; px < size; px += 1) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;

      for (let sy = 0; sy < SS; sy += 1) {
        for (let sx = 0; sx < SS; sx += 1) {
          const x = (px + (sx + 0.5) / SS) / size;
          const y = (py + (sy + 0.5) / SS) / size;
          const shield = shieldCoverage(x, y);
          if (shield <= 0) continue;

          const t = Math.max(0, Math.min(1, (y - 0.1) / 0.82));
          const baseR = BRAND_TOP[0] + (BRAND_BOTTOM[0] - BRAND_TOP[0]) * t;
          const baseG = BRAND_TOP[1] + (BRAND_BOTTOM[1] - BRAND_TOP[1]) * t;
          const baseB = BRAND_TOP[2] + (BRAND_BOTTOM[2] - BRAND_TOP[2]) * t;

          const mark = checkCoverage(x, y);
          r += baseR * (1 - mark) + CHECK[0] * mark;
          g += baseG * (1 - mark) + CHECK[1] * mark;
          b += baseB * (1 - mark) + CHECK[2] * mark;
          a += shield;
        }
      }

      const samples = SS * SS;
      const offset = (py * size + px) * 4;
      blend(pixels, offset, r / samples, g / samples, b / samples, a / samples);
      // Preserve the exact alpha accumulated above to avoid rounding artifacts.
      pixels[offset + 3] = Math.min(255, Math.round((a / samples) * 255));
    }
  }
  void step;
  return encodePng(size, size, pixels);
}

function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  for (const size of SIZES) {
    const png = renderIcon(size);
    const file = resolve(OUT_DIR, `icon-${size}.png`);
    writeFileSync(file, png);
    process.stdout.write(`[icons] icon-${size}.png (${png.length} bytes)\n`);
  }
}

main();
