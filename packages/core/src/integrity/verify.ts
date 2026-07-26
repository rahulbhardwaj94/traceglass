import type { Run, Step } from '../model.js';
import {
  SUPPORTED_HASH_VERSIONS,
  chainAnchor,
  computeRunHash,
  hashStep,
  hashVersionOf,
  isSupportedHashVersion,
  type HashVersion,
} from './hash.js';
import { verifyCommitments } from '../redact/commit.js';

export interface VerifyResult {
  /** True if the stored chain matches a freshly recomputed one. */
  ok: boolean;
  /** Index of the first step whose stored hash/prevHash is wrong; null if intact. */
  brokenStepIndex: number | null;
  /** The id of that step, for reporting; null if intact. */
  brokenStepId: string | null;
  /** Human-readable summary. */
  message: string;
  /** The recomputed run hash (the anchor a verifier can pin). */
  expectedRunHash: string;
  /** The run hash as stored. */
  storedRunHash: string;
  /** The hashing rules applied: 1 for a record that declares none. */
  hashVersion: number;
  /** Committed leaf paths reported as legitimately erased (SPEC §9.4). */
  redactedPaths: string[];
}

/**
 * Recompute the hash chain from scratch and compare to what's stored (§6).
 * Reports the FIRST step whose stored hash or prevHash linkage doesn't match —
 * that's where tampering begins; everything after it is also suspect.
 *
 * ── Version dispatch ─────────────────────────────────────────────────────────
 * Everything below branches on the version the RECORD declares, never on what
 * this build would emit. A record with no `hashVersion` is `tgcanon/1` and goes
 * down the version-1 path, which must stay byte-for-byte what 0.3.0–0.8.0 did:
 * those files are in auditors' hands and the promise is that they keep
 * verifying. A record declaring a version this build does not know is rejected
 * outright rather than verified under the wrong rules (SPEC §10.2).
 */
export function verifyRun(run: Run): VerifyResult {
  const declared = hashVersionOf(run);
  if (!isSupportedHashVersion(declared)) {
    return {
      ok: false,
      brokenStepIndex: null,
      brokenStepId: null,
      message: `Cannot verify: this record declares hashVersion ${declared}, and this build understands ${SUPPORTED_HASH_VERSIONS.join(', ')}. Upgrade traceglass rather than trusting this result.`,
      expectedRunHash: '',
      storedRunHash: run.runHash,
      hashVersion: declared,
      redactedPaths: [],
    };
  }
  const version: HashVersion = declared;

  let prevHash = '';
  let broken: Step | null = null;

  for (const step of run.steps) {
    const expected = hashStep(step, prevHash, version);
    if (step.prevHash !== prevHash || step.hash !== expected) {
      broken = step;
      break;
    }
    prevHash = step.hash;
  }

  const expectedRunHash = computeRunHash(run, chainAnchor(run.steps, version));
  const redactedPaths: string[] = [];

  /*
   * v0.6: for steps carrying per-leaf commitments, the hash covers the
   * COMMITMENTS rather than the raw payload — that is what lets a leaf be
   * redacted without breaking the chain. It also means editing a raw value no
   * longer moves the hash, so payload authenticity MUST be checked against the
   * commitments here. Without this, redaction-enabled runs would silently lose
   * tamper-detection on exactly the data auditors care about.
   *
   * v2 additionally refuses to accept a destroyed leaf as "redacted" unless the
   * record says it was: a missing salt with no matching `redactions` entry (or
   * without the redaction marker in place of the value) is an UNDECLARED
   * erasure and reads as tampering. That is the difference between "this was
   * deliberately redacted" and "someone quietly deleted the incriminating one".
   */
  if (!broken) {
    for (const step of run.steps) {
      if (!step.commitments) continue;
      const check = verifyCommitments(step, step.commitments, step.salts ?? {}, {
        hashVersion: version,
        redactions: step.redactions,
      });
      redactedPaths.push(...check.redacted);
      if (!check.ok) {
        const reason =
          check.undeclared.length > 0
            ? `a committed value at ${check.undeclared.join(', ')} was destroyed without being recorded as a redaction. Data was removed and the record does not admit it.`
            : `payload does not match its commitment at ${check.mismatched.join(', ')}. The recorded data was altered.`;
        return {
          ok: false,
          brokenStepIndex: step.index,
          brokenStepId: step.id,
          message: `Integrity check FAILED: step #${step.index} (${step.id}) ${reason}`,
          expectedRunHash,
          storedRunHash: run.runHash,
          hashVersion: version,
          redactedPaths,
        };
      }
    }
  }

  if (broken) {
    return {
      ok: false,
      brokenStepIndex: broken.index,
      brokenStepId: broken.id,
      message: `Integrity check FAILED: chain broken at step #${broken.index} (${broken.id}). The record was modified after recording.`,
      expectedRunHash,
      storedRunHash: run.runHash,
      hashVersion: version,
      redactedPaths,
    };
  }

  if (run.runHash !== expectedRunHash) {
    // In v2 the anchor also commits to run metadata and the step count, so this
    // is where an edited `currency` or a truncated chain surfaces — say so,
    // because "the anchor was altered" would send an auditor hunting in the
    // steps for something that is sitting in the header.
    const message =
      version === 2
        ? `Integrity check FAILED: the run anchor does not match the record. In tgcanon/2 the anchor covers the run metadata (name, timestamps, status, currency, totals, step count) as well as the step chain, so either the metadata was edited, steps were removed, or the anchor itself was rewritten.`
        : `Integrity check FAILED: runHash does not match the final step hash. The integrity anchor was altered.`;
    return {
      ok: false,
      brokenStepIndex: run.steps.length > 0 ? run.steps.length - 1 : null,
      brokenStepId: run.steps.length > 0 ? run.steps[run.steps.length - 1]!.id : null,
      message,
      expectedRunHash,
      storedRunHash: run.runHash,
      hashVersion: version,
      redactedPaths,
    };
  }

  return {
    ok: true,
    brokenStepIndex: null,
    brokenStepId: null,
    message: 'Integrity check passed: chain intact.',
    expectedRunHash,
    storedRunHash: run.runHash,
    hashVersion: version,
    redactedPaths,
  };
}
