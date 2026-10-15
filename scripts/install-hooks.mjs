#!/usr/bin/env node
/**
 * Installs a `pre-commit` hook that refuses to commit a credential.
 *
 * WHY THIS EXISTS
 * ---------------
 * A GitHub personal access token was written into a plaintext note inside the
 * working directory of a project that was about to be published to a **public**
 * repository. A `.gitignore` entry prevents that specific file, but nothing
 * stops the next token from being pasted into a source file, a config, or a
 * scratch note with a different name.
 *
 * Git history is effectively permanent. Removing a secret afterwards does not
 * un-publish it: forks, caches and scrapers keep copies. The only safe moment
 * to stop a secret is before the first commit.
 *
 * This hook scans the files staged for commit and blocks the commit when a
 * credential pattern matches. It runs entirely locally; nothing is transmitted.
 *
 * Install with:  node scripts/install-hooks.mjs
 * Verify with:   node scripts/scan-secrets.mjs
 */
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HOOKS_DIR = resolve(ROOT, '.githooks');
const HOOK_PATH = join(HOOKS_DIR, 'pre-commit');

const HOOK = `#!/bin/sh
# VOLTRIS - refuses to commit a file containing a credential.
# Installed by scripts/install-hooks.mjs. Delete to disable.

staged=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$staged" ]; then
  exit 0
fi

if ! node "$(git rev-parse --show-toplevel)/scripts/scan-secrets.mjs" --staged; then
  echo ""
  echo "  commit blocked: a credential was found in the files being committed."
  echo "  Revoke it if it is real, then remove it and stage again."
  exit 1
fi
exit 0
`;

mkdirSync(HOOKS_DIR, { recursive: true });
writeFileSync(HOOK_PATH, HOOK, 'utf8');

// A no-op on Windows, where git runs hooks through sh.
try {
  chmodSync(HOOK_PATH, 0o755);
} catch {
  /* permissions are not meaningful on NTFS */
}

process.stdout.write('[hooks] pre-commit hook written to .githooks/pre-commit\n');

if (!existsSync(resolve(ROOT, '.git'))) {
  process.stdout.write('[hooks] not a git repository yet; core.hooksPath was left untouched\n');
  process.stdout.write('[hooks] run this again after `git init` to activate the hook\n');
  process.exit(0);
}

execFileSync('git', ['config', 'core.hooksPath', '.githooks'], { cwd: ROOT, stdio: 'inherit' });
process.stdout.write('[hooks] core.hooksPath set to .githooks\n');
process.stdout.write('[hooks] secret scan is now active on every commit\n');
