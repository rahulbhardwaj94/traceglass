import { createHash, randomBytes } from 'node:crypto';
import { COMMITTED_FIELDS, canonicalize, type CommittedField } from '../integrity/hash.js';

/**
 * Per-leaf salted commitments — the mechanism that lets a record be redacted
 * WITHOUT breaking its hash chain (v0.6).
 *
 * A step's payload fields (`input`, `output`, `dataPayload`) are walked to
 * their JSON leaves. Each leaf gets a random salt and a commitment:
 *
 *   commitment[path] = sha256(salt[path] + canonical(value))
 *
 * The step hash is then computed over the COMMITMENTS, never the raw values
 * (see canonicalStep). Redacting a leaf deletes its raw value and its salt but
 * keeps the commitment — so the hash is unchanged, the chain still verifies,
 * and the signature still holds. Destroying the salt is what makes redaction
 * irreversible: a low-entropy value (an SSN, a boolean) could otherwise be
 * brute-forced straight out of its commitment.
 *
 * Leaves that were NOT redacted stay independently checkable: recompute
 * sha256(salt + value) and compare against the stored commitment.
 */

/** Marker left in place of a redacted leaf value. */
export const REDACTED_MARKER = '[traceglass:redacted]';

export { COMMITTED_FIELDS, type CommittedField } from '../integrity/hash.js';

/** path -> hex sha256 commitment. Paths look like `input`, `input.ssn`, `output[2].id`. */
export type CommitmentMap = Record<string, string>;
/** path -> hex salt. Absent for a path means that leaf has been redacted. */
export type SaltMap = Record<string, string>;

export function commitmentFor(salt: string, value: unknown): string {
  return createHash('sha256')
    .update(salt + canonicalize(value))
    .digest('hex');
}

function newSalt(): string {
  return randomBytes(16).toString('hex');
}

/**
 * Walk a value to its JSON leaves, calling `visit(path, value)`. A leaf is any
 * non-container: string, number, boolean, null, or an EMPTY array/object (so
 * that emptiness itself is committed to and can't be swapped silently).
 */
export function walkLeaves(
  value: unknown,
  visit: (path: string, leaf: unknown) => void,
  basePath = '',
): void {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      visit(basePath, value);
      return;
    }
    value.forEach((item, i) => walkLeaves(item, visit, `${basePath}[${i}]`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>);
    if (keys.length === 0) {
      visit(basePath, value);
      return;
    }
    for (const key of keys) {
      const next = basePath === '' ? key : `${basePath}.${key}`;
      walkLeaves((value as Record<string, unknown>)[key], visit, next);
    }
    return;
  }
  visit(basePath, value);
}

/** Read the leaf at a walk-path out of a container. Returns undefined if absent. */
export function getAtPath(root: unknown, path: string): unknown {
  if (path === '') return root;
  let cur: unknown = root;
  for (const token of tokenizePath(path)) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[token];
  }
  return cur;
}

/** Replace the leaf at a walk-path. Returns a deep copy; does not mutate input. */
export function setAtPath(root: unknown, path: string, next: unknown): unknown {
  if (path === '') return next;
  const copy = structuredClone(root);
  const tokens = tokenizePath(path);
  let cur: unknown = copy;
  for (let i = 0; i < tokens.length - 1; i++) {
    if (cur === null || typeof cur !== 'object') return copy;
    cur = (cur as Record<string, unknown>)[tokens[i]!];
  }
  if (cur !== null && typeof cur === 'object') {
    (cur as Record<string, unknown>)[tokens[tokens.length - 1]!] = next;
  }
  return copy;
}

/** `a.b[2].c` -> ['a','b','2','c'] */
function tokenizePath(path: string): string[] {
  const tokens: string[] = [];
  for (const part of path.split('.')) {
    const m = part.match(/^([^[\]]*)((\[\d+\])*)$/);
    if (!m) {
      tokens.push(part);
      continue;
    }
    if (m[1]) tokens.push(m[1]);
    for (const idx of m[2]?.match(/\d+/g) ?? []) tokens.push(idx);
  }
  return tokens;
}

export interface BuiltCommitments {
  commitments: CommitmentMap;
  salts: SaltMap;
}

/**
 * Build commitments + salts for one payload field. Paths are prefixed with the
 * field name, so `input` with `{ssn: '...'}` yields the path `input.ssn`.
 */
export function buildFieldCommitments(field: CommittedField, value: unknown): BuiltCommitments {
  const commitments: CommitmentMap = {};
  const salts: SaltMap = {};
  walkLeaves(
    value,
    (path, leaf) => {
      const salt = newSalt();
      salts[path] = salt;
      commitments[path] = commitmentFor(salt, leaf);
    },
    field,
  );
  return { commitments, salts };
}

/** Build commitments across every committed field present on a step-like object. */
export function buildCommitments(payload: {
  input?: unknown;
  output?: unknown;
  dataPayload?: unknown;
}): BuiltCommitments {
  const commitments: CommitmentMap = {};
  const salts: SaltMap = {};
  for (const field of COMMITTED_FIELDS) {
    if (payload[field] === undefined) continue;
    const built = buildFieldCommitments(field, payload[field]);
    Object.assign(commitments, built.commitments);
    Object.assign(salts, built.salts);
  }
  return { commitments, salts };
}

export interface CommitmentCheck {
  ok: boolean;
  /** Paths whose visible value does not match its commitment (tampering). */
  mismatched: string[];
  /** Paths whose value is gone and salt destroyed — legitimately redacted. */
  redacted: string[];
  /** Paths still visible and verified against their commitment. */
  verified: string[];
}

/**
 * Check every committed leaf of a step-like payload:
 *   - salt present + value present  -> recompute and compare (verified/mismatched)
 *   - salt absent                   -> redacted (nothing to check; by design)
 */
export function verifyCommitments(
  payload: { input?: unknown; output?: unknown; dataPayload?: unknown },
  commitments: CommitmentMap,
  salts: SaltMap,
): CommitmentCheck {
  const mismatched: string[] = [];
  const redacted: string[] = [];
  const verified: string[] = [];

  for (const [path, commitment] of Object.entries(commitments)) {
    const salt = salts[path];
    if (salt === undefined) {
      redacted.push(path);
      continue;
    }
    const field = path.split(/[.[]/)[0] as CommittedField;
    const rest = path.slice(field.length).replace(/^\./, '');
    const value = getAtPath(payload[field], rest);
    if (commitmentFor(salt, value) === commitment) verified.push(path);
    else mismatched.push(path);
  }

  return { ok: mismatched.length === 0, mismatched, redacted, verified };
}
