import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Run, Step } from '../model.js';
import { analyzeRun } from '../analyze/index.js';
import { withCommitments } from '../redact/redact.js';
import { applyHashChain, computeRunHash, hashStep, type HashVersion } from './hash.js';
import { verifyRun } from './verify.js';
import { keyIdFromPublicKey, signRun, signaturePayload, verifyRunFull } from './signing.js';

/**
 * ADVERSARIAL SUITE — integrity (attacks 1, 2, 10, 11).
 *
 * Every test here is written from the attacker's side of the table. The
 * question is never "does the feature work" but "is the claim on the tin
 * actually true". Where a claim does NOT hold, the test pins the CURRENT
 * behaviour and says so in a `VULNERABILITY:` comment — so the suite stays
 * green while the gap stays visible and impossible to forget.
 *
 * Since the format gained a per-record hash version, several of those pins are
 * now version-scoped: `tgcanon/2` defends, `tgcanon/1` does not and cannot be
 * changed because those records are already in auditors' hands. Both are
 * asserted, side by side, so the split stays honest and neither half can rot.
 */

function keypair(): { priv: string; pub: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    pub: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

function step(
  runId: string,
  index: number,
  payload: Record<string, unknown> = {},
  version: HashVersion = 2,
): Step {
  return withCommitments(
    {
      id: `${runId}:${index}`,
      runId,
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

function run(id: string, steps: Step[], version: HashVersion = 2): Run {
  return applyHashChain(
    analyzeRun({
      id,
      name: id,
      startedAt: steps[0]?.startedAt ?? '2026-01-01T00:00:00.000Z',
      endedAt: steps[steps.length - 1]?.startedAt ?? '2026-01-01T00:00:00.000Z',
      status: 'completed',
      currency: 'USD',
      totals: { tokens: steps.length, cost: steps.length, durationMs: steps.length, steps: steps.length },
      warnings: [],
      steps,
      runHash: '',
    }),
    { hashVersion: version },
  );
}

/** The same run, built and chained under tgcanon/1 — a pre-0.9 record. */
function legacyRun(id: string, steps: Step[]): Run {
  return run(id, steps, 1);
}
function legacyStep(runId: string, index: number, payload: Record<string, unknown> = {}): Step {
  return step(runId, index, payload, 1);
}

describe('ATTACK 1: signature transplant', () => {
  const keys = keypair();

  it('a signature lifted from run A onto run B is rejected', () => {
    const a = signRun(run('runA', [step('runA', 0, { input: { amount: 10 } })]), keys.priv, keys.pub);
    const b = run('runB', [step('runB', 0, { input: { amount: 999999 } })]);

    // The attacker owns run B and wants it to look signed by the victim's key.
    const forged: Run = { ...b, signature: a.signature };

    const result = verifyRunFull(forged);
    expect(result.signature.ok).toBe(false);
    expect(result.ok).toBe(false);
    expect(result.signature.message).toContain('INVALID');
  });

  it('copying A’s runHash across as well does not help — runId is bound too', () => {
    // Naive binding would sign only the runHash, making the signature portable
    // to any record with the same anchor. signaturePayload mixes in runId and
    // signedAt precisely to kill that.
    const a = signRun(run('runA', [step('runA', 0, { input: { amount: 10 } })]), keys.priv, keys.pub);
    const b = run('runB', [step('runB', 0, { input: { amount: 999999 } })]);

    const forged: Run = { ...b, runHash: a.runHash, signature: a.signature };
    const result = verifyRunFull(forged);
    expect(result.signature.ok).toBe(false);
    // The chain check independently rejects the borrowed anchor.
    expect(result.chain.ok).toBe(false);
  });

  it('the signed payload really does differ when only the runId differs', () => {
    // Proves the binding is in the bytes, not just in the outcome above: if
    // these two strings were equal, the transplant test could not fail.
    const at = '2026-01-01T00:00:00.000Z';
    expect(signaturePayload('runA', 'deadbeef', at)).not.toBe(
      signaturePayload('runB', 'deadbeef', at),
    );
    expect(signaturePayload('runA', 'deadbeef', at)).not.toBe(
      signaturePayload('runA', 'deadbeef', '2026-01-02T00:00:00.000Z'),
    );
  });

  it('replaying the signature with a doctored signedAt is rejected', () => {
    // signedAt is inside the signed bytes, so an attacker cannot backdate a
    // genuine signature to claim the record predates an incident.
    const a = signRun(run('runA', [step('runA', 0)]), keys.priv, keys.pub);
    const backdated: Run = {
      ...a,
      signature: { ...a.signature!, signedAt: '2020-01-01T00:00:00.000Z' },
    };
    expect(verifyRunFull(backdated).signature.ok).toBe(false);
  });
});

describe('ATTACK 2: key substitution (re-chain + re-sign with an attacker key)', () => {
  it('VULNERABILITY: a fully re-chained, attacker-signed run passes verifyRunFull', () => {
    /*
     * VULNERABILITY (known, documented limitation — NOT a regression).
     *
     * verifySignature checks the signature against `run.signature.publicKey`,
     * i.e. the key that travels INSIDE the evidence file. An attacker who can
     * write to the store can therefore:
     *   1. edit a payload,
     *   2. rebuild the commitments so the commitment check passes,
     *   3. re-chain every step and the runHash,
     *   4. sign the result with a key they generated themselves.
     * The result verifies clean: chain ok, signature ok, verifyRunFull ok.
     *
     * REAL-WORLD CONSEQUENCE: an insider with filesystem access to
     * ~/.traceglass can rewrite history and hand an auditor a forged evidence
     * file that passes `traceglass verify` with exit 0. The ONLY thing that
     * exposes it is the keyId changing — which nothing currently checks and
     * no auditor is told to look at.
     *
     * WHAT SHOULD HAPPEN: verification must bind to a key the verifier trusts
     * out of band — transparency-log / Rekor anchoring, or at minimum a pinned
     * keyId allowlist. That is not built yet.
     *
     * WHEN ANCHORING LANDS THIS TEST MUST BE UPDATED: the assertions below
     * that read `.ok === true` are pinning the hole, not blessing it.
     */
    const honest = keypair();
    const attacker = keypair();

    const original = signRun(
      run('victim', [
        step('victim', 0, { input: { account: '4471' } }),
        step('victim', 1, { input: { amount: 500000 }, output: { transferred: true } }),
      ]),
      honest.priv,
      honest.pub,
    );
    expect(verifyRunFull(original).ok).toBe(true);

    // 1-3. Rewrite the transfer amount, rebuild commitments, re-chain.
    const tampered = original.steps.map((s, i) =>
      i === 1
        ? ({
            ...s,
            ...withCommitments({ input: { amount: 1 }, output: { transferred: true } }),
          } as Step)
        : s,
    );
    const rechained = applyHashChain({ ...original, steps: tampered });

    // 4. Sign with a key the attacker minted seconds ago.
    const forged = signRun(rechained, attacker.priv, attacker.pub);

    const result = verifyRunFull(forged);
    expect(result.chain.ok).toBe(true); // chain rebuilt, internally consistent
    expect(result.signature.ok).toBe(true); // signed by the key inside the file
    expect(result.ok).toBe(true); // <-- THE HOLE: forgery verifies clean

    // The forged record shows a different amount than the record that was signed.
    expect((forged.steps[1]!.input as { amount: number }).amount).toBe(1);
    expect((original.steps[1]!.input as { amount: number }).amount).toBe(500000);

    // The ONE observable difference an out-of-band anchor would catch today.
    expect(forged.signature!.keyId).not.toBe(original.signature!.keyId);
    expect(forged.runHash).not.toBe(original.runHash);
    expect(keyIdFromPublicKey(attacker.pub)).toBe(forged.signature!.keyId);
  });

  it('the same attack IS caught when the verifier pins the expected keyId', () => {
    // Shows the mitigation that exists today is purely a caller responsibility:
    // compare the keyId against a value obtained out of band. Nothing in
    // verifyRunFull does this for you.
    const honest = keypair();
    const attacker = keypair();
    const original = signRun(run('victim', [step('victim', 0)]), honest.priv, honest.pub);
    const forged = signRun(applyHashChain(original), attacker.priv, attacker.pub);

    const trustedKeyId = keyIdFromPublicKey(honest.pub);
    expect(verifyRunFull(forged).ok).toBe(true); // library says fine
    expect(forged.signature!.keyId === trustedKeyId).toBe(false); // pinning says no
  });

  it('re-chaining WITHOUT a private key still fails — the signature is the backstop', () => {
    // Contrast case: an attacker who cannot sign is caught. This is what makes
    // the test above meaningful rather than "signatures do nothing".
    const honest = keypair();
    const original = signRun(
      run('victim', [step('victim', 0, { input: { amount: 500000 } })]),
      honest.priv,
      honest.pub,
    );
    const tampered = applyHashChain({
      ...original,
      steps: [{ ...original.steps[0]!, ...withCommitments({ input: { amount: 1 } }) } as Step],
    });
    const result = verifyRunFull(tampered); // old signature retained
    expect(result.chain.ok).toBe(true);
    expect(result.signature.ok).toBe(false);
    expect(result.ok).toBe(false);
  });
});

describe('ATTACK 10: hash-chain edge cases', () => {
  it('an empty run verifies only with an empty anchor, in both versions', () => {
    for (const version of [1, 2] as const) {
      const empty: Run = { ...run('e', [step('e', 0, {}, version)], version), steps: [], runHash: '' };
      expect(verifyRun(empty).ok).toBe(true);
      // A fabricated anchor on a stepless run is rejected.
      const faked: Run = { ...empty, runHash: 'deadbeefdeadbeef' };
      expect(verifyRun(faked).ok).toBe(false);
      expect(verifyRun(faked).message).toMatch(/anchor was altered|anchor does not match/);
    }
  });

  it('a single-step run anchors on a header that covers that step’s hash', () => {
    const single = run('s', [step('s', 0)]);
    expect(verifyRun(single).ok).toBe(true);
    // tgcanon/1 anchored literally on the last step hash; tgcanon/2 anchors on
    // the run header, which mixes that hash in. The chain is still what the
    // anchor depends on — there is just more in there now.
    expect(single.runHash).not.toBe(single.steps[0]!.hash);
    expect(legacyRun('s', [legacyStep('s', 0)]).runHash).toBe(
      legacyRun('s', [legacyStep('s', 0)]).steps[0]!.hash,
    );
    // Editing the lone step breaks it at index 0, in both versions.
    for (const r of [single, legacyRun('s', [legacyStep('s', 0)])]) {
      const broken: Run = { ...r, steps: [{ ...r.steps[0]!, label: 'rewritten' }] };
      expect(verifyRun(broken).ok).toBe(false);
      expect(verifyRun(broken).brokenStepIndex).toBe(0);
    }
  });

  it('reordering steps breaks the chain', () => {
    const r = run('p', [step('p', 0), step('p', 1), step('p', 2)]);
    const reordered: Run = { ...r, steps: [r.steps[1]!, r.steps[0]!, r.steps[2]!] };
    const result = verifyRun(reordered);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('chain broken');
  });

  it('a step whose prevHash points at a LATER step is rejected at index 0', () => {
    const r = run('p', [step('p', 0), step('p', 1), step('p', 2)]);
    const looped: Run = {
      ...r,
      steps: [{ ...r.steps[0]!, prevHash: r.steps[2]!.hash }, r.steps[1]!, r.steps[2]!],
    };
    const result = verifyRun(looped);
    expect(result.ok).toBe(false);
    expect(result.brokenStepIndex).toBe(0); // first step must chain from ''
  });

  it('VULNERABILITY: duplicate step indices and ids do not break the chain', () => {
    /*
     * VULNERABILITY: `index` and `id` are hashed as opaque content, but nothing
     * asserts they are unique or monotonic. Two steps can both claim index 0
     * and id "d:0" and the chain still verifies "intact".
     *
     * REAL-WORLD CONSEQUENCE: policy rules that reason about ordering by
     * `index` (requireApprovalFor compares `a.index < s.index`) can be steered
     * by a recorder that emits duplicate or out-of-order indices, and a report
     * reader cannot tell two distinct steps apart by id.
     *
     * WHAT SHOULD HAPPEN: verifyRun should assert step[i].index === i and that
     * ids are unique within the run.
     */
    const duplicated = run('d', [step('d', 0), { ...step('d', 1), index: 0, id: 'd:0' }]);
    expect(verifyRun(duplicated).ok).toBe(true); // <-- pinning the hole
    expect(duplicated.steps.map((s) => s.index)).toEqual([0, 0]);
    expect(new Set(duplicated.steps.map((s) => s.id)).size).toBe(1);
  });

  it('VULNERABILITY: non-monotonic timestamps do not break the chain', () => {
    /*
     * VULNERABILITY: `startedAt` is hashed but never checked for ordering, so a
     * recorded run can claim step #1 happened six years before step #0 and
     * still verify "intact".
     *
     * REAL-WORLD CONSEQUENCE: a timeline handed to an auditor can be internally
     * nonsensical while carrying a clean bill of integrity health.
     *
     * WHAT SHOULD HAPPEN: verifyRun should at least warn when startedAt goes
     * backwards between consecutive steps.
     */
    const backwards = run('n', [
      step('n', 0),
      { ...step('n', 1), startedAt: '2020-01-01T00:00:00.000Z' },
    ]);
    expect(verifyRun(backwards).ok).toBe(true); // <-- pinning the hole
    expect(Date.parse(backwards.steps[1]!.startedAt)).toBeLessThan(
      Date.parse(backwards.steps[0]!.startedAt),
    );
  });

  it('LEGACY (tgcanon/1): an UNSIGNED run can be truncated and still verifies', () => {
    /*
     * VULNERABILITY, version 1 only — kept because those records exist.
     *
     * The v1 chain is a linked list with no commitment to its own length or
     * termination. Any PREFIX of a valid chain is itself a valid chain, so
     * dropping trailing steps and resetting runHash to the new last hash
     * produces a record that reports "chain intact".
     *
     * REAL-WORLD CONSEQUENCE: the most incriminating part of an agent run is
     * usually at the END (the destructive tool call, the error, the final
     * output). On an unsigned v1 run an attacker deletes those steps and
     * `traceglass verify` still exits 0 saying the record was not modified.
     *
     * Fixed in v2 by the test below: the anchor covers stepCount.
     */
    const full = legacyRun('t', [legacyStep('t', 0), legacyStep('t', 1), legacyStep('t', 2)]);
    expect(verifyRun(full).ok).toBe(true);

    const truncated: Run = {
      ...full,
      steps: full.steps.slice(0, 2),
      runHash: full.steps[1]!.hash, // re-anchor on the new last step
    };
    const result = verifyRun(truncated);
    expect(result.ok).toBe(true); // <-- THE HOLE, in v1, permanently
    expect(result.message).toContain('chain intact');
    expect(truncated.steps).toHaveLength(2);
  });

  it('STILL OPEN (tgcanon/2): an UNSIGNED run can be truncated if the attacker re-anchors', () => {
    /*
     * v2 narrows this but does NOT close it, and the honest reason is that it
     * cannot be closed: a two-step run and a three-step run with the last step
     * deleted are the same document. Without an external commitment — a
     * signature, a timestamp, a transparency log — nothing distinguishes them.
     *
     * What v2 does buy: the LAZY version of the attack now fails. Re-pointing
     * `runHash` at the new last step hash is no longer enough, because the
     * anchor is a header hash, not a step hash. The attacker has to rebuild the
     * header — at which point `totals` and `stepCount` visibly describe the
     * shorter run, which is at least a record that does not contradict itself.
     */
    const full = run('t', [step('t', 0), step('t', 1), step('t', 2)]);
    expect(verifyRun(full).ok).toBe(true);
    expect(full.signature).toBeUndefined();

    const lazy: Run = { ...full, steps: full.steps.slice(0, 2), runHash: full.steps[1]!.hash };
    expect(verifyRun(lazy).ok).toBe(false); // v1 accepted exactly this
    expect(verifyRun(lazy).message).toContain('step count');

    const reanchored: Run = { ...lazy, runHash: computeRunHash(lazy) };
    expect(verifyRun(reanchored).ok).toBe(true); // <-- STILL THE HOLE, unsigned only
    expect(reanchored.steps).toHaveLength(2);
    // The tell an auditor can still use: the header now claims three steps'
    // worth of totals over two steps. Nothing enforces that today (SPEC §12.11).
    expect(reanchored.totals.steps).toBe(3);
  });

  it('truncation IS caught once the run is signed, in both versions', () => {
    // The signature covers the anchor, so moving the anchor invalidates it.
    // In v1 this was the ONLY defence against truncation.
    for (const version of [1, 2] as const) {
      const keys = keypair();
      const steps = [step('t', 0, {}, version), step('t', 1, {}, version), step('t', 2, {}, version)];
      const signed = signRun(run('t', steps, version), keys.priv, keys.pub);
      const truncated: Run = {
        ...signed,
        steps: signed.steps.slice(0, 2),
        runHash: signed.steps[1]!.hash,
      };
      const result = verifyRunFull(truncated);
      expect(result.signature.ok).toBe(false);
      expect(result.ok).toBe(false);
    }
  });

  it('appending a fabricated step to a signed run is caught', () => {
    for (const version of [1, 2] as const) {
      const keys = keypair();
      const signed = signRun(run('a', [step('a', 0, {}, version)], version), keys.priv, keys.pub);
      const extra = step('a', 1, { output: { exonerating: true } }, version);
      const prev = signed.steps[0]!.hash;
      const chainedExtra: Step = {
        ...extra,
        prevHash: prev,
        hash: hashStep({ ...extra, prevHash: prev }, prev, version),
      };
      const extended: Run = {
        ...signed,
        steps: [...signed.steps, chainedExtra],
        runHash: chainedExtra.hash,
      };
      const result = verifyRunFull(extended);
      expect(result.signature.ok).toBe(false);
      expect(result.ok).toBe(false);
    }
  });
});

describe('ATTACK 11: rewriting run metadata on a signed record', () => {
  /*
   * The most valuable edit in this format is not in the steps at all.
   *
   * Every `cost` is a bare number whose unit lives only in `run.currency`.
   * Flipping "INR" -> "USD" restates the whole record ~85×. `status` turns a
   * failed run into a completed one. `totals` is what a reader actually reads.
   * In tgcanon/1 NONE of it was covered by the chain or the signature, and all
   * of it could be edited on a signed record that still verified clean.
   *
   * tgcanon/2 folds the run header into the anchor, and the signature already
   * covered the anchor, so both layers close at once.
   */
  const keys = keypair();

  const EDITS: Array<[string, (r: Run) => Run]> = [
    ['currency INR->USD', (r) => ({ ...r, currency: 'USD' })],
    ['status failed->completed', (r) => ({ ...r, status: 'completed' })],
    ['totals.cost restated', (r) => ({ ...r, totals: { ...r.totals, cost: 0.01 } })],
    ['totals.tokens restated', (r) => ({ ...r, totals: { ...r.totals, tokens: 999_999 } })],
    ['name rewritten', (r) => ({ ...r, name: 'a different agent entirely' })],
    ['startedAt backdated', (r) => ({ ...r, startedAt: '2020-01-01T00:00:00.000Z' })],
    ['endedAt stretched', (r) => ({ ...r, endedAt: '2030-01-01T00:00:00.000Z' })],
  ];

  function signedRun(version: HashVersion): Run {
    const base = run('meta', [step('meta', 0, { input: { amount: 500000 } }, version)], version);
    const withMeta: Run = { ...base, currency: 'INR', status: 'failed' };
    // Re-anchor so the header the signature covers is the one on the record.
    return signRun({ ...withMeta, runHash: computeRunHash(withMeta) }, keys.priv, keys.pub);
  }

  it('LEGACY (tgcanon/1): every metadata field is editable on a signed, verifying record', () => {
    // VULNERABILITY, version 1 only, and permanent: nothing covers the header.
    const signed = signedRun(1);
    expect(verifyRunFull(signed).ok).toBe(true);
    for (const [name, edit] of EDITS) {
      const result = verifyRunFull(edit(signed));
      expect([name, result.ok]).toEqual([name, true]); // <-- THE HOLE
      expect([name, result.signature.ok]).toEqual([name, true]);
    }
  });

  it('DEFENDED (tgcanon/2): every one of those edits breaks the anchor AND the signature', () => {
    const signed = signedRun(2);
    expect(verifyRunFull(signed).ok).toBe(true);
    for (const [name, edit] of EDITS) {
      const result = verifyRunFull(edit(signed));
      expect([name, result.ok]).toEqual([name, false]);
      expect([name, result.chain.ok]).toEqual([name, false]);
      expect(result.chain.message).toContain('run metadata');

      /*
       * Note where the defence actually sits. The signature is over the STORED
       * `runHash`, which the attacker did not touch, so it still validates in
       * isolation — SPEC §9.5(d) says as much, and it is exactly why §9.3 must
       * run first and why a verifier MUST NOT report the signature verdict on
       * its own. The chain check is what notices that the stored anchor no
       * longer describes the record it is attached to.
       */
      expect([name, result.signature.ok]).toEqual([name, true]);

      // And repairing it properly is out of reach: re-anchoring the edited run
      // invalidates the signature, which the attacker cannot remake.
      const repaired = { ...edit(signed), runHash: computeRunHash(edit(signed)) };
      const after = verifyRunFull(repaired);
      expect([name, after.chain.ok]).toEqual([name, true]);
      expect([name, after.signature.ok]).toEqual([name, false]);
      expect([name, after.ok]).toEqual([name, false]);
    }
  });

  it('DEFENDED (tgcanon/2): metadata is covered even when the run is UNSIGNED', () => {
    // SPEC §12.1 proposed fixing this at the signature layer, which would have
    // left unsigned records exactly as exposed as before. Putting it in the
    // anchor covers them too.
    const unsigned = { ...run('meta', [step('meta', 0)]), currency: 'INR' };
    const anchored: Run = { ...unsigned, runHash: computeRunHash(unsigned) };
    expect(verifyRun(anchored).ok).toBe(true);
    expect(anchored.signature).toBeUndefined();
    expect(verifyRun({ ...anchored, currency: 'USD' }).ok).toBe(false);
  });

  it('a v2 record cannot be downgraded to v1 to escape the new rules', () => {
    // Stripping `hashVersion` makes a verifier read the record as tgcanon/1 —
    // where the header is not covered. But v1 hashes the STEPS differently too,
    // so the chain fails at step 0 long before the anchor is reached.
    const signed = signedRun(2);
    const downgraded: Run = { ...signed, currency: 'USD' };
    delete (downgraded as { hashVersion?: number }).hashVersion;
    const result = verifyRun(downgraded);
    expect(result.ok).toBe(false);
    expect(result.hashVersion).toBe(1);
    expect(result.brokenStepIndex).toBe(0);
  });

  it('a record declaring an unknown hash version is refused, not guessed at', () => {
    // The failure direction that matters: a verifier must never apply the rules
    // it happens to know to a record written under rules it does not.
    const future: Run = { ...run('f', [step('f', 0)]), hashVersion: 99 };
    const result = verifyRun(future);
    expect(result.ok).toBe(false);
    expect(result.message).toContain('hashVersion 99');
    expect(result.message).toContain('Upgrade traceglass');
  });
});
