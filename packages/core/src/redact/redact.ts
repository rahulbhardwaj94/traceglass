import type { Run, Step, RedactionRecord } from '../model.js';
import {
  COMMITTED_FIELDS,
  DEFAULT_HASH_VERSION,
  chainSteps,
  computeRunHash,
  hashVersionOf,
  isSupportedHashVersion,
  type CommittedField,
  type HashVersion,
} from '../integrity/hash.js';
import { sealRedactions } from '../integrity/signing.js';
import {
  REDACTED_MARKER,
  buildCommitments,
  getAtTokens,
  setAtTokens,
  splitCommitmentPath,
  walkLeaves,
  type CommitmentMap,
  type SaltMap,
} from './commit.js';

/**
 * Redaction (v0.6). Two distinct mechanisms, deliberately kept apart:
 *
 * 1. CAPTURE-TIME pattern scrubbing (`scrubPayload`) — sensitive values are
 *    replaced before the record is hashed, so the original never lands on
 *    disk at all. Strongest privacy; nothing to verify because nothing was
 *    ever committed to.
 *
 * 2. POST-HOC redaction (`redactStep` / `redactRun`) — the value was captured
 *    and committed to, and is now destroyed along with its salt. The step's
 *    commitment survives, so the hash chain and signature STILL VERIFY, and
 *    every sibling leaf remains independently checkable. This is what answers
 *    "delete this person's data" without invalidating the audit record.
 */

/** A named pattern for automatic detection of sensitive values. */
export interface RedactionPattern {
  name: string;
  regex: RegExp;
}

/**
 * Default detectors. Deliberately conservative — a false positive destroys
 * data irreversibly, so these favour precision over recall.
 */
export const DEFAULT_PATTERNS: RedactionPattern[] = [
  { name: 'email', regex: /[\w.+-]+@[\w-]+\.[\w.]{2,}/ },
  { name: 'credit-card', regex: /\b(?:\d[ -]*?){13,19}\b/ },
  { name: 'ssn', regex: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: 'aadhaar', regex: /\b\d{4}\s?\d{4}\s?\d{4}\b/ },
  { name: 'private-key', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'bearer-token', regex: /\b(?:sk-|ghp_|Bearer\s+)[A-Za-z0-9_\-.]{16,}/ },
];

export function patternsByName(names: string[]): RedactionPattern[] {
  const selected: RedactionPattern[] = [];
  for (const name of names) {
    const found = DEFAULT_PATTERNS.find((p) => p.name === name);
    if (!found) {
      throw new Error(
        `Unknown redaction pattern "${name}". Available: ${DEFAULT_PATTERNS.map((p) => p.name).join(', ')}.`,
      );
    }
    selected.push(found);
  }
  return selected;
}

/** Does any pattern match this leaf's textual form? Returns the pattern name. */
function matchPattern(leaf: unknown, patterns: RedactionPattern[]): string | null {
  if (leaf === null || leaf === undefined) return null;
  const text = typeof leaf === 'string' ? leaf : JSON.stringify(leaf);
  if (typeof text !== 'string') return null;
  for (const p of patterns) {
    if (p.regex.test(text)) return p.name;
  }
  return null;
}

export interface ScrubResult<T> {
  value: T;
  /** Paths (relative to the field) that were scrubbed, with the pattern name. */
  hits: Array<{ path: string; pattern: string }>;
}

/**
 * CAPTURE-TIME scrubbing of one payload field: replace every leaf matching a
 * pattern with the redaction marker, BEFORE commitments are built. The
 * original value is never committed to and never stored.
 */
export function scrubPayload(
  field: CommittedField,
  value: unknown,
  patterns: RedactionPattern[],
  version: HashVersion = DEFAULT_HASH_VERSION,
): ScrubResult<unknown> {
  const hits: Array<{ path: string; pattern: string }> = [];
  let out = value;
  walkLeaves(
    value,
    (path, leaf) => {
      const pattern = matchPattern(leaf, patterns);
      if (!pattern) return;
      hits.push({ path, pattern });
      const { tokens } = splitCommitmentPath(path, version);
      out = setAtTokens(out, tokens, REDACTED_MARKER);
    },
    field,
    version,
  );
  return { value: out, hits };
}

/** Scrub every payload field of a step-like object at capture time. */
export function scrubStepPayload(
  payload: { input?: unknown; output?: unknown; dataPayload?: unknown },
  patterns: RedactionPattern[],
  version: HashVersion = DEFAULT_HASH_VERSION,
): {
  payload: { input?: unknown; output?: unknown; dataPayload?: unknown };
  redactions: RedactionRecord[];
} {
  const next = { ...payload };
  const redactions: RedactionRecord[] = [];
  const at = new Date().toISOString();
  for (const field of COMMITTED_FIELDS) {
    if (next[field] === undefined) continue;
    const { value, hits } = scrubPayload(field, next[field], patterns, version);
    next[field] = value;
    for (const hit of hits) {
      redactions.push({ path: hit.path, at, reason: `pattern:${hit.pattern}`, by: 'pattern' });
    }
  }
  return { payload: next, redactions };
}

/** Find committed leaf paths in a step whose values match any pattern. */
export function findPatternPaths(
  step: Step,
  patterns: RedactionPattern[],
  version: HashVersion = DEFAULT_HASH_VERSION,
): string[] {
  const paths: string[] = [];
  for (const field of COMMITTED_FIELDS) {
    if (step[field] === undefined) continue;
    walkLeaves(
      step[field],
      (path, leaf) => {
        if (leaf === REDACTED_MARKER) return; // already gone
        if (matchPattern(leaf, patterns)) paths.push(path);
      },
      field,
      version,
    );
  }
  return paths;
}

export class RedactionError extends Error {}

/**
 * POST-HOC redact one committed leaf of a step: destroy the value and its
 * salt, keep the commitment, and record the event. The step's `hash` is
 * returned untouched — that is the whole point, and `redactRun` asserts it.
 *
 * Throws if the step has no commitments (a pre-0.6 record): those must go
 * through the explicitly-labelled legacy path, which re-chains and re-signs.
 */
export function redactStep(
  step: Step,
  path: string,
  opts: { reason?: string; by?: RedactionRecord['by']; hashVersion?: HashVersion } = {},
): Step {
  const version = opts.hashVersion ?? 1;
  if (!step.commitments) {
    throw new RedactionError(
      `Step ${step.id} carries no commitments (recorded before v0.6). Redact it with the legacy path, which re-chains and re-signs the run.`,
    );
  }
  if (!(path in step.commitments)) {
    throw new RedactionError(`Step ${step.id} has no committed leaf at "${path}".`);
  }
  const { field, tokens } = splitCommitmentPath(path, version);
  if (!COMMITTED_FIELDS.includes(field as CommittedField)) {
    throw new RedactionError(`Path "${path}" does not target a payload field.`);
  }

  const salts: SaltMap = { ...(step.salts ?? {}) };
  delete salts[path]; // destroying the salt is what makes this irreversible

  const next: Step = {
    ...step,
    [field]: setAtTokens(step[field as CommittedField], tokens, REDACTED_MARKER),
    salts,
    redactions: [
      ...(step.redactions ?? []),
      {
        path,
        at: new Date().toISOString(),
        ...(opts.reason !== undefined ? { reason: opts.reason } : {}),
        by: opts.by ?? 'manual',
      },
    ],
  };
  return next;
}

export interface RedactRunResult {
  run: Run;
  /** Every path removed, across all steps. */
  redacted: string[];
}

/**
 * Redact leaves across a run by explicit `<stepId>#<path>` targets and/or by
 * pattern match. The run's `runHash` and every step `hash` are unchanged; the
 * caller can (and the CLI does) verify the chain afterwards to prove it.
 *
 * On a `hashVersion: 2` record, pass `sealWith` to attest to the result. A
 * sealed redaction is one a keyholder has signed for; an unsealed one is a
 * declared-but-unattested claim by whoever last wrote the file. Both verify —
 * the difference is reported, not hidden — but only the sealed form can be
 * defended as authorised.
 */
export function redactRun(
  run: Run,
  opts: {
    paths?: string[]; // "stepId#input.ssn", or "input.ssn" to apply to every step
    patterns?: RedactionPattern[];
    reason?: string;
    /** Keys to seal the redaction log with (`hashVersion: 2`). */
    sealWith?: { privateKeyPem: string; publicKeyPem: string };
  },
): RedactRunResult {
  const version = redactionVersionOf(run);
  const redacted: string[] = [];
  const steps = run.steps.map((step) => {
    let next = step;
    const targets = new Set<string>();

    for (const raw of opts.paths ?? []) {
      const [stepId, leafPath] = raw.includes('#') ? raw.split('#', 2) : [null, raw];
      if (stepId !== null && stepId !== step.id) continue;
      if (leafPath) targets.add(leafPath);
    }
    if (opts.patterns && opts.patterns.length > 0) {
      for (const p of findPatternPaths(step, opts.patterns, version)) targets.add(p);
    }

    for (const path of targets) {
      if (!next.commitments || !(path in next.commitments)) continue; // not committed here
      next = redactStep(next, path, {
        ...(opts.reason !== undefined ? { reason: opts.reason } : {}),
        by: opts.patterns && opts.patterns.length > 0 ? 'pattern' : 'manual',
        hashVersion: version,
      });
      redacted.push(`${step.id}#${path}`);
    }
    return next;
  });

  let next: Run = { ...run, steps };
  if (opts.sealWith && version === 2) {
    next = sealRedactions(next, opts.sealWith.privateKeyPem, opts.sealWith.publicKeyPem);
  }
  return { run: next, redacted };
}

/** The path/redaction rules a run's own declared version implies. */
function redactionVersionOf(run: Run): HashVersion {
  const declared = hashVersionOf(run);
  return isSupportedHashVersion(declared) ? declared : 1;
}

/**
 * LEGACY retrofit for pre-0.6 records, which hashed raw values and therefore
 * cannot be redacted without changing their hashes.
 *
 * This path removes the values and RE-CHAINS the run, producing a NEW chain
 * and a new anchor. That is a materially weaker guarantee than commitment-based
 * redaction: a verifier can confirm the redacted record is internally
 * consistent and signed by the redactor, but can no longer prove what the
 * original content was. The caller MUST re-sign the result and should surface
 * the distinction — `traceglass redact --legacy` says so explicitly.
 *
 * Returns the re-chained run; the `runHash` WILL differ from the original.
 *
 * The re-chain preserves whatever version the record declared. A pre-0.6 record
 * declares nothing, so it stays `tgcanon/1`: silently promoting it to 2 would
 * change the hashed field set of a record whose provenance is already the weak
 * point here, and would surprise anyone diffing it against the original.
 */
export function redactLegacyRun(
  run: Run,
  opts: { paths?: string[]; patterns?: RedactionPattern[]; reason?: string },
): RedactRunResult & { previousRunHash: string } {
  const version = redactionVersionOf(run);
  const previousRunHash = run.runHash;
  const redacted: string[] = [];
  const at = new Date().toISOString();

  const steps = run.steps.map((step) => {
    let next = step;
    const targets = new Set<string>();

    for (const raw of opts.paths ?? []) {
      const [stepId, leafPath] = raw.includes('#') ? raw.split('#', 2) : [null, raw];
      if (stepId !== null && stepId !== step.id) continue;
      if (leafPath) targets.add(leafPath);
    }
    if (opts.patterns && opts.patterns.length > 0) {
      for (const field of COMMITTED_FIELDS) {
        if (step[field] === undefined) continue;
        walkLeaves(
          step[field],
          (path, leaf) => {
            if (leaf === REDACTED_MARKER) return;
            if (matchPattern(leaf, opts.patterns!)) targets.add(path);
          },
          field,
          version,
        );
      }
    }

    for (const path of targets) {
      const { field, tokens } = splitCommitmentPath(path, version);
      if (!COMMITTED_FIELDS.includes(field as CommittedField)) continue;
      const payloadField = field as CommittedField;
      if (getAtTokens(next[payloadField], tokens) === undefined) continue;
      next = {
        ...next,
        [payloadField]: setAtTokens(next[payloadField], tokens, REDACTED_MARKER),
        redactions: [
          ...(next.redactions ?? []),
          {
            path,
            at,
            reason: opts.reason ?? 'legacy redaction (record re-chained)',
            by: opts.patterns && opts.patterns.length > 0 ? 'pattern' : 'manual',
          },
        ],
      };
      redacted.push(`${step.id}#${path}`);
    }
    return next;
  });

  // Re-chain: the raw values were hashed, so their removal moves every hash.
  const rechained = chainSteps(steps, version);
  const rebuilt: Run = {
    ...run,
    steps: rechained,
    // The old signature covered the old anchor; it is now meaningless. So is
    // any redaction seal, which bound the old anchor too.
    ...(run.signature ? { signature: undefined } : {}),
    ...(run.redactionSeal ? { redactionSeal: undefined } : {}),
  };

  return {
    run: { ...rebuilt, runHash: computeRunHash(rebuilt) },
    redacted,
    previousRunHash,
  };
}

/**
 * Attach commitments to a step-like payload — used by capture paths (SDK,
 * ingest) to make a record redactable later.
 *
 * `version` selects the path syntax; it MUST match the version the enclosing
 * run is chained under, because the commitment paths are hashed as the keys of
 * the commitment view (SPEC §5.2).
 */
export function withCommitments<
  T extends { input?: unknown; output?: unknown; dataPayload?: unknown },
>(
  payload: T,
  version: HashVersion = DEFAULT_HASH_VERSION,
): T & { commitments: CommitmentMap; salts: SaltMap } {
  const { commitments, salts } = buildCommitments(payload, version);
  return { ...payload, commitments, salts };
}
