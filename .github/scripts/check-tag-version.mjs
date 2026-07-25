#!/usr/bin/env node
/**
 * Refuse to publish when the git tag and the package versions disagree.
 *
 * traceglass ships tamper-evident evidence; "which commit produced this
 * tarball" has to have exactly one answer. This asserts:
 *
 *   1. the tag is v<semver>
 *   2. every publishable workspace is at exactly that version
 *   3. the exact-pin cross-dependencies (sdk -> core, cli -> core) match too
 *
 * Usage: node .github/scripts/check-tag-version.mjs v0.8.0
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const tag = process.argv[2];
if (!tag) {
  console.error('usage: check-tag-version.mjs <tag>');
  process.exit(2);
}

const match = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(tag);
if (!match) {
  console.error(`✗ tag "${tag}" is not of the form v<semver> (e.g. v0.8.0)`);
  process.exit(1);
}
const expected = match[1];

// Workspaces that actually get published. @traceglass/web is private.
const publishable = ['packages/core', 'packages/sdk', 'packages/cli'];

const errors = [];

function readPkg(dir) {
  return JSON.parse(readFileSync(join(root, dir, 'package.json'), 'utf8'));
}

for (const dir of publishable) {
  const pkg = readPkg(dir);

  if (pkg.private) {
    errors.push(`${pkg.name}: marked private but listed as publishable`);
    continue;
  }

  if (pkg.version !== expected) {
    errors.push(`${pkg.name}: version ${pkg.version} != tag ${expected}`);
  }

  // sdk and cli pin @traceglass/core exactly; a stale pin would publish a
  // package that resolves to the previous core at install time.
  const pinned = pkg.dependencies?.['@traceglass/core'];
  if (pinned !== undefined && pinned !== expected) {
    errors.push(`${pkg.name}: depends on @traceglass/core@${pinned}, expected ${expected}`);
  }
}

if (errors.length > 0) {
  console.error(`✗ tag/version mismatch for ${tag}:`);
  for (const e of errors) console.error(`    - ${e}`);
  process.exit(1);
}

console.log(`✓ ${tag}: all publishable packages at ${expected}, core pins consistent`);
