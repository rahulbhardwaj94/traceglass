import { describe, expect, it } from 'vitest';
import type { Run, Step } from '../model.js';
import { analyzeRun } from '../analyze/index.js';
import { applyHashChain, type HashVersion } from '../integrity/hash.js';
import { verifyRun } from '../integrity/verify.js';
import { sealRedactions, verifyRedactionSeal, verifyRunFull } from '../integrity/signing.js';
import { generateKeyPairSync } from 'node:crypto';
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

function committed(
  index: number,
  payload: Record<string, unknown>,
  version: HashVersion = 2,
): Step {
  return withCommitments(
    {
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
    },
    version,
  ) as Step;
}

function makeRun(steps: Step[], version: HashVersion = 2): Run {
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
    { hashVersion: version },
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

  it('LEGACY (tgcanon/1): deleting a salt hides tampering behind a fake "redacted" claim', () => {
    /*
     * VULNERABILITY, version 1 only, and permanent — those records exist.
     *
     * v1 `verifyCommitments` treats a missing salt as "legitimately redacted"
     * and skips the check entirely. An attacker who edits a payload can
     * therefore also delete that leaf's salt, and verification reports the leaf
     * as redacted rather than as tampered.
     *
     * REAL-WORLD CONSEQUENCE: "the amount was 999999, and the record says that
     * leaf was erased for GDPR reasons" is a much softer story to an auditor
     * than "the record was altered". Tamper-evidence degrades to tamper-
     * plausible-deniability.
     *
     * Fixed in v2 by the two tests below.
     */
    const run = makeRun([committed(0, { input: { amount: 100 } }, 1)], 1);
    const original = run.steps[0]!;

    const salts: SaltMap = { ...original.salts! };
    delete salts['input.amount'];
    const forged: Step = { ...original, input: { amount: 999999 }, salts };

    const check = verifyCommitments(forged, original.commitments!, salts, { hashVersion: 1 });
    expect(check.ok).toBe(true); // <-- THE HOLE, in v1
    expect(check.redacted).toContain('input.amount');
    expect(check.mismatched).toEqual([]);

    // ...and the whole run passes verification carrying the forged amount.
    const forgedRun: Run = { ...run, steps: [forged] };
    expect(verifyRun(forgedRun).ok).toBe(true); // <-- THE HOLE, in v1
    expect((forgedRun.steps[0]!.input as { amount: number }).amount).toBe(999999);

    // The two signals that WOULD expose it, unchecked in v1:
    expect(forged.input).not.toEqual({ amount: REDACTED_MARKER });
    expect(forged.redactions).toBeUndefined();
  });

  it('DEFENDED (tgcanon/2): destroying a salt without declaring the redaction FAILS', () => {
    // v2 will not accept a missing salt as erasure on the attacker's say-so.
    // The record must ADMIT the destruction: the value must read as the marker
    // AND the step's `redactions` log must name the path. This is the whole
    // "quietly removed" vs "deliberately redacted" distinction.
    const run = makeRun([committed(0, { input: { amount: 100 } })]);
    const original = run.steps[0]!;
    const salts: SaltMap = { ...original.salts! };
    delete salts['input.amount'];

    // (a) value rewritten, salt destroyed, nothing declared
    const forged: Step = { ...original, input: { amount: 999999 }, salts };
    const check = verifyCommitments(forged, original.commitments!, salts, { hashVersion: 2 });
    expect(check.ok).toBe(false);
    expect(check.undeclared).toContain('input.amount');
    expect(check.redacted).toEqual([]);

    const result = verifyRun({ ...run, steps: [forged] });
    expect(result.ok).toBe(false);
    expect(result.message).toContain('without being recorded as a redaction');

    // (b) value DELETED outright, salt destroyed, nothing declared — the
    // "silently destroy the one incriminating leaf" attack.
    const vanished: Step = { ...original, input: {}, salts };
    expect(verifyRun({ ...run, steps: [vanished] }).ok).toBe(false);

    // (c) marker in place but still no redactions entry — half-declared is not
    // declared. An attacker who knows the marker must also write the log.
    const markerOnly: Step = { ...original, input: { amount: REDACTED_MARKER }, salts };
    expect(verifyRun({ ...run, steps: [markerOnly] }).ok).toBe(false);

    // (d) a redactions entry for a DIFFERENT path does not launder this one.
    const wrongPath: Step = {
      ...original,
      input: { amount: REDACTED_MARKER },
      salts,
      redactions: [{ path: 'input.somethingElse', at: '2026-01-01T00:00:00.000Z', by: 'manual' }],
    };
    expect(verifyRun({ ...run, steps: [wrongPath] }).ok).toBe(false);
  });

  it('DEFENDED (tgcanon/2): a genuine redaction still verifies, and still keeps the anchor', () => {
    // The defence must not break the feature: a real `redactRun` redaction
    // declares itself, so it passes — and the anchor is untouched, which is the
    // property that lets a signed record survive a GDPR erasure.
    const run = makeRun([committed(0, { input: { ssn: '123-45-6789', keep: 'x' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'], reason: 'erasure' });

    const result = verifyRun(redacted);
    expect(result.ok).toBe(true);
    expect(result.redactedPaths).toContain('input.ssn');
    expect(redacted.runHash).toBe(run.runHash);
    expect(redacted.steps[0]!.hash).toBe(run.steps[0]!.hash);
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

describe('ATTACK 4d: ambiguous commitment paths (the false-alarm bug)', () => {
  /*
   * The worst failure mode an evidence product has is not a missed alarm. It is
   * a FALSE one: telling an auditor "the recorded data was altered" about a
   * record nobody touched, and sending them hunting for fraud that did not
   * happen.
   *
   * v1 builds commitment paths by bare concatenation, so `{"user.email": x}`
   * and `{"user": {"email": x}}` both produce `input.user.email`. Read back on
   * the flat-key record that path resolves to nothing, the commitment does not
   * match, and an untouched record fails verification. Dotted keys are not
   * exotic — config maps, header maps and MongoDB-style documents all hit it.
   */
  const NASTY: Array<[string, Record<string, unknown>]> = [
    ['a literal dotted key', { 'user.email': 'a@b.com' }],
    ['a key that mimics an array index', { 'rows[0]': 'not an array' }],
    ['a key containing a backslash', { 'a\\b': 1 }],
    ['an empty key', { '': 'edge' }],
    ['a dotted key beside real nesting', { 'user.email': 'flat', user: { email: 'nested' } }],
    ['a key with both separators', { 'a.b[2]\\c': true }],
  ];

  it('LEGACY (tgcanon/1): honest records with dotted keys FAIL verification', () => {
    // VULNERABILITY, version 1 only, and permanent.
    const run = makeRun([committed(0, { input: { 'user.email': 'a@b.com' } }, 1)], 1);
    const result = verifyRun(run);
    expect(result.ok).toBe(false); // <-- THE FALSE ALARM
    expect(result.message).toContain('The recorded data was altered.');
    // Nobody touched it: the record is exactly what the capture path produced.
    expect((run.steps[0]!.input as Record<string, unknown>)['user.email']).toBe('a@b.com');

    // The nested control passes, which is what makes this a collision rather
    // than a general breakage.
    const control = makeRun([committed(0, { input: { user: { email: 'a@b.com' } } }, 1)], 1);
    expect(verifyRun(control).ok).toBe(true);
  });

  it('DEFENDED (tgcanon/2): every one of those honest records verifies', () => {
    for (const [name, input] of NASTY) {
      const run = makeRun([committed(0, { input })]);
      expect([name, verifyRun(run).ok]).toEqual([name, true]);
    }
  });

  it('DEFENDED (tgcanon/2): a flat dotted key and real nesting get DISTINCT paths', () => {
    // The collision itself is gone, not merely worked around: the two shapes
    // commit to different paths, so neither can be substituted for the other.
    const flat = committed(0, { input: { 'user.email': 'x' } });
    const nested = committed(0, { input: { user: { email: 'x' } } });
    expect(Object.keys(flat.commitments!)).toEqual(['input.user\\.email']);
    expect(Object.keys(nested.commitments!)).toEqual(['input.user.email']);
  });

  it('DEFENDED (tgcanon/2): tampering with a dotted-key value is still caught', () => {
    // The fix must not turn a false alarm into a blind spot.
    const run = makeRun([committed(0, { input: { 'user.email': 'a@b.com' } })]);
    const tampered: Run = {
      ...run,
      steps: [{ ...run.steps[0]!, input: { 'user.email': 'attacker@evil.com' } }],
    };
    const result = verifyRun(tampered);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('The recorded data was altered.');
  });

  it('DEFENDED (tgcanon/2): a dotted-key leaf can be redacted like any other', () => {
    const run = makeRun([committed(0, { input: { 'user.email': 'a@b.com', keep: 'x' } })]);
    const { run: redacted, redacted: paths } = redactRun(run, {
      paths: ['input.user\\.email'],
      reason: 'erasure',
    });
    expect(paths).toEqual(['r:0#input.user\\.email']);
    expect((redacted.steps[0]!.input as Record<string, unknown>)['user.email']).toBe(
      REDACTED_MARKER,
    );
    expect((redacted.steps[0]!.input as Record<string, unknown>).keep).toBe('x');
    expect(verifyRun(redacted).ok).toBe(true);
    expect(redacted.runHash).toBe(run.runHash);
  });
});

describe('ATTACK 4e: forging the redaction log', () => {
  /*
   * v2's structural rule guarantees a destroyed leaf is DECLARED. It cannot, on
   * its own, prove the declaration is honest: whoever can write the file can
   * write a plausible `redactions` entry too. Closing that needs a key, and the
   * key is exactly what an attacker does not have.
   *
   * The redaction seal is that second signature. The original run signature
   * covers the anchor and must survive redaction untouched — that is the
   * property the whole commitment scheme exists for — so the seal is separate,
   * and binds {runId, runHash, redactionsHash, sealedAt}.
   */
  function keypair(): { priv: string; pub: string } {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return {
      priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
      pub: publicKey.export({ type: 'spki', format: 'pem' }) as string,
    };
  }
  const keys = keypair();

  function sealedRedaction(): Run {
    const run = makeRun([committed(0, { input: { ssn: '123-45-6789', keep: 'x' } })]);
    return redactRun(run, {
      paths: ['input.ssn'],
      reason: 'gdpr-17',
      sealWith: { privateKeyPem: keys.priv, publicKeyPem: keys.pub },
    }).run;
  }

  it('an unsealed redaction verifies but is reported as UNATTESTED', () => {
    // Deliberately not a hard failure: the record does declare the erasure, and
    // failing it would make redaction impossible for anyone without the key.
    // The auditor is told the difference instead of it being hidden.
    const run = makeRun([committed(0, { input: { ssn: '123-45-6789' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });
    const result = verifyRunFull(redacted);
    expect(result.ok).toBe(true);
    expect(result.redaction.attested).toBe(false);
    expect(result.redaction.message).toContain('UNATTESTED');
    expect(result.redaction.paths).toEqual(['r:0#input.ssn']);
  });

  it('a sealed redaction is reported as attested, and the run anchor is untouched', () => {
    const run = makeRun([committed(0, { input: { ssn: '123-45-6789', keep: 'x' } })]);
    const sealed = redactRun(run, {
      paths: ['input.ssn'],
      sealWith: { privateKeyPem: keys.priv, publicKeyPem: keys.pub },
    }).run;
    const result = verifyRunFull(sealed);
    expect(result.ok).toBe(true);
    expect(result.redaction.attested).toBe(true);
    expect(result.redaction.keyId).toBe(sealed.redactionSeal!.keyId);
    expect(sealed.runHash).toBe(run.runHash);
  });

  it('FABRICATING a redaction entry breaks the seal', () => {
    // "This step also had an SSN we lawfully erased" — for a leaf never touched.
    const sealed = sealedRedaction();
    const forged: Run = {
      ...sealed,
      steps: [
        {
          ...sealed.steps[0]!,
          redactions: [
            ...sealed.steps[0]!.redactions!,
            { path: 'input.keep', at: '2026-01-01T00:00:00.000Z', reason: 'invented', by: 'manual' },
          ],
        },
      ],
    };
    const result = verifyRunFull(forged);
    expect(result.ok).toBe(false);
    expect(result.redaction.ok).toBe(false);
    expect(result.redaction.message).toContain('does not match the sealed digest');
  });

  it('DELETING the redaction log breaks the seal AND the structural rule', () => {
    // Hiding that an erasure happened at all.
    const sealed = sealedRedaction();
    const stripped: Run = { ...sealed, steps: [{ ...sealed.steps[0]!, redactions: [] }] };
    expect(verifyRunFull(stripped).redaction.ok).toBe(false);
    // Caught independently: the salt is gone and nothing declares it any more.
    expect(verifyRun(stripped).ok).toBe(false);
  });

  it('EDITING a reason or a timestamp breaks the seal', () => {
    const sealed = sealedRedaction();
    const edited: Run = {
      ...sealed,
      steps: [
        {
          ...sealed.steps[0]!,
          redactions: [{ ...sealed.steps[0]!.redactions![0]!, reason: 'routine cleanup' }],
        },
      ],
    };
    expect(verifyRunFull(edited).redaction.ok).toBe(false);
  });

  it('re-sealing with an attacker key leaves the keyId as the only tell', () => {
    // The same residual limitation as the run signature (SPEC §11.1): an
    // attacker who re-seals with their own key produces a self-consistent
    // record. What they cannot produce is one sealed by the key an auditor
    // independently expects.
    const attacker = keypair();
    const sealed = sealedRedaction();
    const resealed = sealRedactions(sealed, attacker.priv, attacker.pub);
    expect(verifyRedactionSeal(resealed).ok).toBe(true);
    expect(resealed.redactionSeal!.keyId).not.toBe(sealed.redactionSeal!.keyId);
  });

  it('a seal cannot be transplanted from another run', () => {
    const a = sealedRedaction();
    const b = makeRun([committed(0, { input: { ssn: '999-99-9999' } })]);
    const { run: bRedacted } = redactRun(b, { paths: ['input.ssn'] });
    const transplanted: Run = { ...bRedacted, redactionSeal: a.redactionSeal! };
    expect(verifyRedactionSeal(transplanted).ok).toBe(false);
  });

  it('sealing is refused on a tgcanon/1 record rather than silently doing nothing', () => {
    const legacy = makeRun([committed(0, { input: { ssn: '123-45-6789' } }, 1)], 1);
    expect(() => sealRedactions(legacy, keys.priv, keys.pub)).toThrow(/hashVersion 2/);
  });
});
