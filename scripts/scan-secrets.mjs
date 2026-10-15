#!/usr/bin/env node
/**
 * Scans for credentials before they enter git history.
 *
 * Why this is a build step and not a convention: git history is effectively
 * permanent. A secret committed once cannot be unpublished - forks, CI caches,
 * mirrors and scrapers keep copies - so the only safe moment to stop one is
 * before the first commit. A personal access token was written in plaintext into
 * this working directory while the project was being prepared for a public
 * repository, which is exactly the situation this script is meant to make
 * impossible to repeat.
 *
 * Usage:
 *   node scripts/scan-secrets.mjs            scan the working tree
 *   node scripts/scan-secrets.mjs --staged   scan files staged for commit
 *   node scripts/scan-secrets.mjs --json     machine-readable output
 *
 * Nothing is transmitted. Everything runs locally.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { extname, relative, resolve, join } from 'node:path';

const asJson = process.argv.includes('--json');
const stagedOnly = process.argv.includes('--staged');
const ROOT = process.cwd();

/** Patterns, each with an explicit reason for the finding. */
const PATTERNS = [
  { id: 'github-pat-classic', re: /\bghp_[A-Za-z0-9]{36}\b/, why: 'GitHub personal access token (classic)' },
  { id: 'github-pat-fine', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/, why: 'GitHub fine-grained personal access token' },
  { id: 'github-oauth', re: /\bgho_[A-Za-z0-9]{36}\b/, why: 'GitHub OAuth access token' },
  { id: 'github-app', re: /\b(?:ghs|ghu)_[A-Za-z0-9]{36}\b/, why: 'GitHub server-to-server or user-to-server token' },
  { id: 'github-refresh', re: /\bghr_[A-Za-z0-9]{36,}\b/, why: 'GitHub refresh token' },
  { id: 'slack', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, why: 'Slack token' },
  { id: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/, why: 'AWS access key id' },
  { id: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/, why: 'Google API key' },
  { id: 'npm-token', re: /\bnpm_[A-Za-z0-9]{36}\b/, why: 'npm access token' },
  { id: 'private-key-block', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, why: 'Private key' },
  { id: 'api-secret-key', re: /\bsk-[A-Za-z0-9]{48}\b/, why: 'API secret key' },
];

/**
 * Files whose matches are documentation of this very scanner rather than live
 * secrets. Everything else that matches is a finding.
 */
const SELF_REFERENTIAL = new Set(['scripts/scan-secrets.mjs', 'SECURITY.md']);

const TEXT_EXTENSIONS = new Set([
  '.ts', '.js', '.mjs', '.cjs', '.json', '.md', '.txt', '.yml', '.yaml', '.toml',
  '.html', '.css', '.sh', '.env', '.xml', '.ini', '.cfg', '.pem', '.key',
]);

const IGNORED_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'artifacts', 'coverage', 'test-results',
  '.githooks', 'playwright-report', 'blob-report',
]);

/** Generated data that legitimately contains long opaque strings. */
const IGNORED_FILES = new Set([
  'src/generated/psl.json',
  'package-lock.json',
  'vendor/public_suffix_list.dat',
]);

function* walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else if (entry.isFile()) yield full;
  }
}

function gitStagedFiles() {
  try {
    const out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    return out.split(/\r?\n/).filter(Boolean);
  } catch {
    return null;
  }
}

function collectTargets() {
  if (stagedOnly) {
    const staged = gitStagedFiles();
    if (staged === null) {
      process.stderr.write('[secrets] not a git repository, or nothing staged; scanning the working tree instead\n');
    } else {
      return staged.map((f) => resolve(ROOT, f));
    }
  }
  return [...walk(ROOT)];
}

const findings = [];
let scanned = 0;

for (const file of collectTargets()) {
  const rel = relative(ROOT, file).replace(/\\/g, '/');
  if (IGNORED_FILES.has(rel)) continue;
  if (SELF_REFERENTIAL.has(rel)) continue;
  if (!TEXT_EXTENSIONS.has(extname(file).toLowerCase())) continue;
  if (!existsSync(file)) continue;

  let content;
  try {
    if (statSync(file).size > 4 * 1024 * 1024) continue; // data, not source
    content = readFileSync(file, 'utf8');
  } catch {
    continue;
  }

  // Undecodable bytes mean a binary file; a pasted token cannot survive there.
  if (content.includes('�')) continue;

  scanned += 1;
  const lines = content.split(/\r?\n/);

  for (const pattern of PATTERNS) {
    if (!pattern.re.test(content)) continue;
    const line = lines.findIndex((l) => pattern.re.test(l)) + 1;
    // The location is reported; the value never is.
    findings.push({ file: rel, line, id: pattern.id, why: pattern.why });
  }
}

if (asJson) {
  process.stdout.write(`${JSON.stringify({ ok: findings.length === 0, scanned, findings }, null, 2)}\n`);
} else if (findings.length === 0) {
  process.stdout.write(`[secrets] scanned ${scanned} files, no credentials found\n`);
} else {
  for (const f of findings) {
    process.stderr.write(`  ${f.file}:${f.line}  ${f.why} (${f.id})\n`);
  }
  process.stderr.write(`\n[secrets] ${findings.length} potential credential(s) in ${scanned} scanned files.\n`);
  process.stderr.write('[secrets] The value is never printed. Revoke it, remove it, scan again.\n');
}

process.exit(findings.length === 0 ? 0 : 1);
