/** Type declarations for the dependency-free ZIP writer used by the packager. */

export interface ZipEntry {
  /** Path inside the archive. Must use `/` separators and be relative. */
  name: string;
  data: Uint8Array;
  /** Epoch milliseconds; encoded into the MS-DOS date/time fields. */
  mtime: number;
  /** Unix mode; only the executable bit is carried across. */
  mode: number;
}

export function createZip(entries: readonly ZipEntry[]): Buffer;
export function crc32(buf: Uint8Array): number;
export function listZipEntries(buf: Uint8Array): string[];
