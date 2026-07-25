import { describe, expect, it } from 'vitest';
import type { Run, Step } from '../model.js';
import { analyzeRun } from '../analyze/index.js';
import { applyHashChain } from '../integrity/hash.js';
import { verifyRun } from '../integrity/verify.js';
import {
  REDACTED_MARKER,
  buildCommitments,
  commitmentFor,
  verifyCommitments,
  type CommitmentMap,
  type SaltMap,
} from './commit.js';
import { redactRun, withCommitments } from './redact.js';

/**
 * ADVERSARIAL SUITE — commitments and salts (attack 4).
 *
 * The erasure claim rests entirely on one mechanism: destroying the salt makes
 * the surviving commitment useless for recovering the value. These tests attack
 * that mechanism directly rather than asserting that redaction "works".
 */

function committed(index: number, payload: Record<string, unknown>): Step {
  return withCommitments({
    id: `r:${index}`,
    runId: 'r',
    index,
    type: 'tool_call' as const,
    label: `step ${index}`,
    startedAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
    durationMs: 1,
    tokens: 1,
    cost: 1,
    toolName: 'db',
    spanId: `span-${index}`,
    hash: '',
    prevHash: '',
    ...payload,
  }) as Step;
}

function makeRun(steps: Step[]): Run {
  return applyHashChain(
    analyzeRun({
      id: 'r',
      name: 'r',
      startedAt: steps[0]!.startedAt,
      endedAt: steps[steps.length - 1]!.startedAt,
      status: 'completed',
      currency: 'USD',
      totals: { tokens: 1, cost: 1, durationMs: 1, steps: steps.length },
      warnings: [],
      steps,
      runHash: '',
    }),
  );
}

describe('ATTACK 4a: salt reuse across leaves', () => {
  it('the production commit path never reuses a salt — not within a field, a step, or a run', () => {
    // This is the invariant everything else in this file depends on. If two
    // leaves ever shared a salt, identical values would produce identical
    // commitments and redacting one would be undone by reading the other.
    const built = buildCommitments({
      input: { a: 'same', b: 'same', c: 'same' },
      output: { d: 'same', e: 'same' },
      dataPayload: { f: 'same' },
    });
    const salts = Object.values(built.salts);
    expect(salts).toHaveLength(6);
    expect(new Set(salts).size).toBe(6);

    // Consequence: six leaves holding the SAME value get six distinct commitments.
    const commitments = Object.values(built.commitments);
    expect(new Set(commitments).size).toBe(6);
  });

  it('salts carry 128 bits of entropy, so guessing one is not a strategy', () => {
    const { salts } = buildCommitments({ input: { x: 1 } });
    const salt = salts['input.x']!;
    expect(salt).toMatch(/^[0-9a-f]{32}$/); // 16 random bytes, hex
  });

  it('two runs recording the SAME secret produce unrelated commitments', () => {
    // Cross-record correlation attack: given a commitment from a redacted run,
    // can an attacker find another run holding the same value? Not by
    // commitment equality — the salts differ.
    const a = committed(0, { input: { ssn: '123-45-6789' } });
    const b = committed(0, { input: { ssn: '123-45-6789' } });
    expect(a.commitments!['input.ssn']).not.toBe(b.commitments!['input.ssn']);
  });

  it('ATTACK: if a salt WERE reused, redacting one leaf would disclose the other', () => {
    // The counter-factual, to show the invariant above is load-bearing rather
    // than incidental. We hand-build a step with a deliberately shared salt.
    const sharedSalt = 'f'.repeat(32);
    const secret = '123-45-6789';
    const commitments: CommitmentMap = {
      'input.redactMe': commitmentFor(sharedSalt, secret),
      'input.leftVisible': commitmentFor(sharedSalt, secret),
    };
    const salts: SaltMap = { 'input.leftVisible': sharedSalt }; // redactMe's salt destroyed
    const payload = { input: { redactMe: REDACTED_MARKER, leftVisible: secret } };

    // An attacker recomputes the destroyed leaf's commitment from the visible
    // sibling's salt+value and gets an exact match — erasure defeated.
    const recovered = commitmentFor(salts['input.leftVisible']!, payload.input.leftVisible);
    expect(recovered).toBe(commitments['input.redactMe']);

    // Which is exactly why buildCommitments must never do this:
    const real = buildCommitments({ input: { redactMe: secret, leftVisible: secret } });
    expect(real.salts['input.redactMe']).not.toBe(real.salts['input.leftVisible']);
    expect(real.commitments['input.redactMe']).not.toBe(real.commitments['input.leftVisible']);
  });

  it('redacting one leaf discloses nothing about a sibling holding the same value', () => {
    // The end-to-end version of the above, through the real redact path.
    const run = makeRun([committed(0, { input: { ssn: '123-45-6789', copy: '123-45-6789' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });
    const s = redacted.steps[0]!;

    expect((s.input as { ssn: string }).ssn).toBe(REDACTED_MARKER);
    expect(s.salts!['input.ssn']).toBeUndefined();

    // The surviving sibling's salt cannot reproduce the destroyed commitment.
    const siblingSalt = s.salts!['input.copy']!;
    expect(commitmentFor(siblingSalt, '123-45-6789')).not.toBe(s.commitments!['input.ssn']);
    // (It does reproduce its OWN commitment — the sibling stays verifiable.)
    expect(commitmentFor(siblingSalt, '123-45-6789')).toBe(s.commitments!['input.copy']);
  });
});

describe('ATTACK 4b: brute-forcing a low-entropy value out of its commitment', () => {
  const LOW_ENTROPY_GUESSES: unknown[] = [
    true,
    false,
    null,
    0,
    1,
    '',
    'yes',
    'no',
    'approved',
    'denied',
    REDACTED_MARKER,
  ];

  it('WITH the salt, a low-entropy leaf is trivially brute-forced — this is why salts die', () => {
    // Establishes that the value really IS guessable, so the next test is a
    // real test and not a tautology.
    const step = committed(0, { input: { approved: true } });
    const salt = step.salts!['input.approved']!;
    const target = step.commitments!['input.approved']!;

    const found = LOW_ENTROPY_GUESSES.filter((g) => commitmentFor(salt, g) === target);
    expect(found).toEqual([true]);
  });

  it('after redaction the salt is GONE, and the same brute force finds nothing', () => {
    const run = makeRun([committed(0, { input: { approved: true, ssn: '123-45-6789' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.approved', 'input.ssn'] });
    const s = redacted.steps[0]!;

    // The salt is genuinely absent from the record — not blanked, not zeroed.
    expect(s.salts!['input.approved']).toBeUndefined();
    expect('input.approved' in s.salts!).toBe(false);
    expect(JSON.stringify(s)).not.toContain(run.steps[0]!.salts!['input.approved']!);

    // Without a salt there is nothing to hash against. Every plausible salt an
    // attacker might try (empty, zeros, the marker, a sibling's salt) fails.
    const target = s.commitments!['input.approved']!;
    const candidateSalts = ['', '0'.repeat(32), 'f'.repeat(32), s.salts!['input.ssn'] ?? ''];
    for (const salt of candidateSalts) {
      for (const guess of LOW_ENTROPY_GUESSES) {
        expect(commitmentFor(salt, guess)).not.toBe(target);
      }
    }
  });

  it('the destroyed salt is not recoverable from anywhere else in the run', () => {
    const run = makeRun([
      committed(0, { input: { ssn: '123-45-6789', keep: 'x' } }),
      committed(1, { output: { note: 'unrelated' } }),
    ]);
    const originalSalt = run.steps[0]!.salts!['input.ssn']!;
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });

    // Full-record sweep: the salt string appears nowhere in the serialized run.
    expect(JSON.stringify(redacted)).not.toContain(originalSalt);
    // Nor does the raw value.
    expect(JSON.stringify(redacted)).not.toContain('123-45-6789');
    // The commitment survives (that is the point) but is inert.
    expect(redacted.steps[0]!.commitments!['input.ssn']).toBe(
      run.steps[0]!.commitments!['input.ssn'],
    );
  });

  it('re-supplying the correct value cannot un-redact the leaf', () => {
    // An attacker who KNOWS the value tries to restore it and pass verification.
    const run = makeRun([committed(0, { input: { ssn: '123-45-6789' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });
    const s = redacted.steps[0]!;

    const restored: Step = { ...s, input: { ssn: '123-45-6789' } };
    const check = verifyCommitments(restored, s.commitments!, s.salts!);
    // With no salt the path is simply reported as redacted; the restored value
    // is NOT accepted as verified, so it carries no evidentiary weight.
    expect(check.redacted).toContain('input.ssn');
    expect(check.verified).not.toContain('input.ssn');
  });
});

describe('ATTACK 4c: forging around the commitment check', () => {
  it('swapping a raw value while keeping the commitment is detected', () => {
    const run = makeRun([committed(0, { input: { amount: 100 } })]);
    const tampered: Run = {
      ...run,
      steps: [{ ...run.steps[0]!, input: { amount: 999999 } }],
    };
    expect(tampered.steps[0]!.hash).toBe(run.steps[0]!.hash); // chain blind to it
    const result = verifyRun(tampered);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('input.amount');
  });

  it('VULNERABILITY: deleting a salt hides tampering behind a fake "redacted" claim', () => {
    /*
     * VULNERABILITY: `verifyCommitments` treats a missing salt as "legitimately
     * redacted" and skips the check entirely. An attacker who edits a payload
     * can therefore also delete that leaf's salt, and verification reports the
     * leaf as redacted rather than as tampered.
     *
     * The tell is that the visible value is NOT the redaction marker — a
     * genuinely redacted leaf always reads `[traceglass:redacted]`, and there
     * should be a matching entry in `step.redactions`. Neither is checked.
     *
     * REAL-WORLD CONSEQUENCE: "the amount was 999999, and the record says that
     * leaf was erased for GDPR reasons" is a much softer story to an auditor
     * than "the record was altered". Tamper-evidence degrades to tamper-
     * plausible-deniability.
     *
     * WHAT SHOULD HAPPEN: a saltless leaf whose visible value is not the
     * redaction marker (or which has no corresponding `redactions` entry)
     * should be reported as MISMATCHED, not redacted.
     */
    const run = makeRun([committed(0, { input: { amount: 100 } })]);
    const original = run.steps[0]!;

    const salts: SaltMap = { ...original.salts! };
    delete salts['input.amount'];
    const forged: Step = { ...original, input: { amount: 999999 }, salts };

    const check = verifyCommitments(forged, original.commitments!, salts);
    expect(check.ok).toBe(true); // <-- THE HOLE
    expect(check.redacted).toContain('input.amount');
    expect(check.mismatched).toEqual([]);

    // ...and the whole run passes verification carrying the forged amount.
    const forgedRun: Run = { ...run, steps: [forged] };
    expect(verifyRun(forgedRun).ok).toBe(true); // <-- THE HOLE
    expect((forgedRun.steps[0]!.input as { amount: number }).amount).toBe(999999);

    // The two signals that WOULD expose it, unchecked today:
    expect(forged.input).not.toEqual({ amount: REDACTED_MARKER });
    expect(forged.redactions).toBeUndefined();
  });

  it('adding a NEW committed leaf after the fact is detected', () => {
    // An attacker appends an exonerating field with a matching commitment.
    const run = makeRun([committed(0, { input: { amount: 100 } })]);
    const s = run.steps[0]!;
    const extraSalt = 'a'.repeat(32);
    const forged: Step = {
      ...s,
      input: { amount: 100, authorizedBy: 'the-cfo' },
      commitments: { ...s.commitments!, 'input.authorizedBy': commitmentFor(extraSalt, 'the-cfo') },
      salts: { ...s.salts!, 'input.authorizedBy': extraSalt },
    };
    // The commitment map is hashed, so adding to it moves the step hash and
    // breaks the chain.
    const forgedRun: Run = { ...run, steps: [forged] };
    const result = verifyRun(forgedRun);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('chain broken');
  });

  it('an empty container is committed to, so it cannot be swapped for content', () => {
    // walkLeaves commits empty arrays/objects as leaves precisely so that
    // "there was nothing here" is itself provable.
    const run = makeRun([committed(0, { input: { attachments: [] } })]);
    const tampered: Run = {
      ...run,
      steps: [{ ...run.steps[0]!, input: { attachments: ['smoking-gun.pdf'] } }],
    };
    expect(verifyRun(tampered).ok).toBe(false);
  });
});
