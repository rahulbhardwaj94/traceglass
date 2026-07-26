import { createHash, randomBytes } from 'node:crypto';
import {
  COMMITTED_FIELDS,
  DEFAULT_HASH_VERSION,
  canonicalize,
  type CommittedField,
  type HashVersion,
} from '../integrity/hash.js';
import type { RedactionRecord } from '../model.js';

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
 *
 * ── Path versions ────────────────────────────────────────────────────────────
 * `hashVersion: 1` builds paths by bare concatenation, so `{"user.email": x}`
 * and `{"user": {"email": x}}` both produce `input.user.email`. On the flat-key
 * record the path then reads back as nothing, the commitment does not match,
 * and an UNTOUCHED record is reported as altered. A false integrity alarm is
 * the worst failure this product has, so `hashVersion: 2` escapes `\`, `.` and
 * `[` inside key segments and tokenizes with an escape-aware scanner. Version 1
 * keeps its exact behaviour, bugs and all, because records in the wild depend
 * on those bytes.
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

/* ── path construction ─────────────────────────────────────────────────────── */

/**
 * Escape a single object key for a `hashVersion: 2` path. `\`, `.` and `[` are
 * the three characters that carry structural meaning; everything else, `]`
 * included, is unambiguous once `[` can only ever start an array index.
 */
export function escapePathSegment(key: string): string {
  return key.replace(/[\\.[]/g, (c) => `\\${c}`);
}

/**
 * Tokenize a `hashVersion: 2` path into container keys, honouring escapes and
 * preserving empty segments (so a literal `""` key is addressable, unlike v1).
 *
 * `input.rows[0].user\.email` -> ['input', 'rows', '0', 'user.email']
 */
export function tokenizePathV2(path: string): string[] {
  const tokens: string[] = [];
  let seg = '';
  let segOpen = true; // are we accumulating a key, or sitting just after `]`?
  for (let i = 0; i < path.length; i++) {
    const c = path[i]!;
    if (c === '\\' && i + 1 < path.length) {
      seg += path[++i];
      segOpen = true;
      continue;
    }
    if (c === '.') {
      if (segOpen) {
        tokens.push(seg);
        seg = '';
      }
      segOpen = true;
      continue;
    }
    if (c === '[') {
      const close = path.indexOf(']', i);
      const digits = close === -1 ? null : path.slice(i + 1, close);
      if (digits !== null && /^\d+$/.test(digits)) {
        if (segOpen) {
          tokens.push(seg);
          seg = '';
        }
        tokens.push(digits);
        segOpen = false;
        i = close;
        continue;
      }
      // Not a well-formed index: treat as an ordinary character. Producers
      // never emit this (they escape `[`), but a hand-edited path might.
    }
    seg += c;
    segOpen = true;
  }
  if (segOpen) tokens.push(seg);
  return tokens;
}

/** `a.b[2].c` -> ['a','b','2','c'] — the `hashVersion: 1` tokenizer, unchanged. */
function tokenizePathV1(path: string): string[] {
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

/**
 * Split a full commitment path into its payload field and the tokens that
 * address the leaf inside it.
 *
 * The v1 branch reproduces the shipped behaviour exactly — including the cases
 * where it reads back the wrong node (SPEC §12.5) — because those bytes are the
 * format for every record published up to 0.8.0.
 */
export function splitCommitmentPath(
  path: string,
  version: HashVersion = 1,
): { field: string; tokens: string[] } {
  if (version === 2) {
    const tokens = tokenizePathV2(path);
    return { field: tokens[0] ?? '', tokens: tokens.slice(1) };
  }
  const field = path.split(/[.[]/)[0]!;
  const rest = path.slice(field.length).replace(/^\./, '');
  return { field, tokens: rest === '' ? [] : tokenizePathV1(rest) };
}

/** Read the value addressed by pre-tokenized path segments. */
export function getAtTokens(root: unknown, tokens: string[]): unknown {
  let cur: unknown = root;
  for (const token of tokens) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[token];
  }
  return cur;
}

/** Replace the value addressed by pre-tokenized segments. Returns a deep copy. */
export function setAtTokens(root: unknown, tokens: string[], next: unknown): unknown {
  if (tokens.length === 0) return next;
  const copy = structuredClone(root);
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

/** Read the leaf at a walk-path out of a container. Returns undefined if absent. */
export function getAtPath(root: unknown, path: string, version: HashVersion = 1): unknown {
  if (version === 1 && path === '') return root;
  return getAtTokens(root, version === 2 ? tokenizePathV2(path) : tokenizePathV1(path));
}

/** Replace the leaf at a walk-path. Returns a deep copy; does not mutate input. */
export function setAtPath(
  root: unknown,
  path: string,
  next: unknown,
  version: HashVersion = 1,
): unknown {
  if (path === '') return next;
  const tokens = version === 2 ? tokenizePathV2(path) : tokenizePathV1(path);
  // Deliberately NOT delegating to setAtTokens: v1 must keep its exact
  // behaviour when tokenization yields nothing for a non-empty path.
  const copy = structuredClone(root);
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

/* ── leaf walking ──────────────────────────────────────────────────────────── */

/**
 * Walk a value to its JSON leaves, calling `visit(path, value)`. A leaf is any
 * non-container: string, number, boolean, null, or an EMPTY array/object (so
 * that emptiness itself is committed to and can't be swapped silently).
 *
 * PRODUCER side, so it defaults to the current version — the same default
 * `applyHashChain` uses. A commitment map built under one version and hashed
 * under another is a latent bug that only shows up on keys containing `.`,
 * `[` or `\`, i.e. exactly the case version 2 exists to fix, so the two
 * defaults are deliberately kept in lockstep.
 */
export function walkLeaves(
  value: unknown,
  visit: (path: string, leaf: unknown) => void,
  basePath = '',
  version: HashVersion = DEFAULT_HASH_VERSION,
): void {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      visit(basePath, value);
      return;
    }
    value.forEach((item, i) => walkLeaves(item, visit, `${basePath}[${i}]`, version));
    return;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>);
    if (keys.length === 0) {
      visit(basePath, value);
      return;
    }
    for (const key of keys) {
      const seg = version === 2 ? escapePathSegment(key) : key;
      const next = basePath === '' ? seg : `${basePath}.${seg}`;
      walkLeaves((value as Record<string, unknown>)[key], visit, next, version);
    }
    return;
  }
  visit(basePath, value);
}

export interface BuiltCommitments {
  commitments: CommitmentMap;
  salts: SaltMap;
}

/**
 * Build commitments + salts for one payload field. Paths are prefixed with the
 * field name, so `input` with `{ssn: '...'}` yields the path `input.ssn`.
 */
export function buildFieldCommitments(
  field: CommittedField,
  value: unknown,
  version: HashVersion = DEFAULT_HASH_VERSION,
): BuiltCommitments {
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
    version,
  );
  return { commitments, salts };
}

/** Build commitments across every committed field present on a step-like object. */
export function buildCommitments(
  payload: {
    input?: unknown;
    output?: unknown;
    dataPayload?: unknown;
  },
  version: HashVersion = DEFAULT_HASH_VERSION,
): BuiltCommitments {
  const commitments: CommitmentMap = {};
  const salts: SaltMap = {};
  for (const field of COMMITTED_FIELDS) {
    if (payload[field] === undefined) continue;
    const built = buildFieldCommitments(field, payload[field], version);
    Object.assign(commitments, built.commitments);
    Object.assign(salts, built.salts);
  }
  return { commitments, salts };
}

/* ── verification ──────────────────────────────────────────────────────────── */

export interface CommitmentCheck {
  ok: boolean;
  /** Paths whose visible value does not match its commitment (tampering). */
  mismatched: string[];
  /** Paths whose value is gone and salt destroyed — legitimately redacted. */
  redacted: string[];
  /** Paths still visible and verified against their commitment. */
  verified: string[];
  /**
   * `hashVersion: 2` only. Paths whose salt is gone but which are NOT declared
   * as redactions — a value destroyed without a record of it. Treated as
   * tampering, not as erasure: this is the "quietly removed by someone hiding
   * something" case that version 1 could not tell apart from a lawful redaction.
   */
  undeclared: string[];
}

export interface VerifyCommitmentsOptions {
  /** Which path/redaction rules apply. Defaults to 1 (the legacy behaviour). */
  hashVersion?: HashVersion;
  /** The step's redaction log, needed by the v2 erasure-discipline rule. */
  redactions?: RedactionRecord[] | undefined;
}

/**
 * Check every committed leaf of a step-like payload.
 *
 * v1:  salt present -> recompute and compare (verified/mismatched)
 *      salt absent  -> redacted; nothing to check, by design. This is the hole:
 *                      an attacker can delete a value AND its salt and the leaf
 *                      is reported as lawfully erased.
 *
 * v2:  salt absent is only accepted as a redaction when the record SAYS SO —
 *      the visible value must be the redaction marker AND the step's
 *      `redactions` log must name the path. Otherwise the path is `undeclared`
 *      and the check fails. Erasure stays possible; SILENT erasure does not.
 */
export function verifyCommitments(
  payload: {
    input?: unknown;
    output?: unknown;
    dataPayload?: unknown;
    redactions?: RedactionRecord[];
  },
  commitments: CommitmentMap,
  salts: SaltMap,
  opts: VerifyCommitmentsOptions = {},
): CommitmentCheck {
  const version = opts.hashVersion ?? 1;
  const redactions = opts.redactions ?? payload.redactions ?? [];
  const declared = new Set(redactions.map((r) => r.path));

  const mismatched: string[] = [];
  const redacted: string[] = [];
  const verified: string[] = [];
  const undeclared: string[] = [];

  for (const [path, commitment] of Object.entries(commitments)) {
    const salt = salts[path];
    const { field, tokens } = splitCommitmentPath(path, version);
    const value = getAtTokens((payload as Record<string, unknown>)[field], tokens);

    if (salt === undefined) {
      if (version === 2 && !(declared.has(path) && value === REDACTED_MARKER)) {
        undeclared.push(path);
        continue;
      }
      redacted.push(path);
      continue;
    }
    if (commitmentFor(salt, value) === commitment) verified.push(path);
    else mismatched.push(path);
  }

  return {
    ok: mismatched.length === 0 && undeclared.length === 0,
    mismatched,
    redacted,
    verified,
    undeclared,
  };
}
