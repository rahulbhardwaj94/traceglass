import type { Run, Step } from '../model.js';
import { hashStep } from './hash.js';
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
}

/**
 * Recompute the hash chain from scratch and compare to what's stored (§6).
 * Reports the FIRST step whose stored hash or prevHash linkage doesn't match —
 * that's where tampering begins; everything after it is also suspect.
 */
export function verifyRun(run: Run): VerifyResult {
  let prevHash = '';
  let broken: Step | null = null;

  for (const step of run.steps) {
    const expected = hashStep(step, prevHash);
    if (step.prevHash !== prevHash || step.hash !== expected) {
      broken = step;
      break;
    }
    prevHash = step.hash;
  }

  /*
   * v0.6: for steps carrying per-leaf commitments, the hash covers the
   * COMMITMENTS rather than the raw payload — that is what lets a leaf be
   * redacted without breaking the chain. It also means editing a raw value no
   * longer moves the hash, so payload authenticity MUST be checked against the
   * commitments here. Without this, redaction-enabled runs would silently lose
   * tamper-detection on exactly the data auditors care about.
   */
  if (!broken) {
    for (const step of run.steps) {
      if (!step.commitments) continue;
      const check = verifyCommitments(step, step.commitments, step.salts ?? {});
      if (!check.ok) {
        return {
          ok: false,
          brokenStepIndex: step.index,
          brokenStepId: step.id,
          message: `Integrity check FAILED: step #${step.index} (${step.id}) payload does not match its commitment at ${check.mismatched.join(', ')}. The recorded data was altered.`,
          expectedRunHash: hashChainAnchor(run.steps),
          storedRunHash: run.runHash,
        };
      }
    }
  }

  const expectedRunHash = run.steps.length > 0 ? hashChainAnchor(run.steps) : '';

  if (broken) {
    return {
      ok: false,
      brokenStepIndex: broken.index,
      brokenStepId: broken.id,
      message: `Integrity check FAILED: chain broken at step #${broken.index} (${broken.id}). The record was modified after recording.`,
      expectedRunHash,
      storedRunHash: run.runHash,
    };
  }

  if (run.runHash !== prevHash) {
    return {
      ok: false,
      brokenStepIndex: run.steps.length > 0 ? run.steps.length - 1 : null,
      brokenStepId: run.steps.length > 0 ? run.steps[run.steps.length - 1]!.id : null,
      message: `Integrity check FAILED: runHash does not match the final step hash. The integrity anchor was altered.`,
      expectedRunHash,
      storedRunHash: run.runHash,
    };
  }

  return {
    ok: true,
    brokenStepIndex: null,
    brokenStepId: null,
    message: 'Integrity check passed: chain intact.',
    expectedRunHash,
    storedRunHash: run.runHash,
  };
}

/** Recompute the run anchor (final step hash) independent of stored hashes. */
function hashChainAnchor(steps: Step[]): string {
  let prevHash = '';
  for (const step of steps) {
    prevHash = hashStep(step, prevHash);
  }
  return prevHash;
}
