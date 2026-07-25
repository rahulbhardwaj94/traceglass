import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { Run, Step } from '../model.js';
import { analyzeRun } from '../analyze/index.js';
import { withCommitments } from '../redact/redact.js';
import { applyHashChain, hashStep } from './hash.js';
import { verifyRun } from './verify.js';
import { keyIdFromPublicKey, signRun, signaturePayload, verifyRunFull } from './signing.js';

/**
 * ADVERSARIAL SUITE — integrity (attacks 1, 2, 10).
 *
 * Every test here is written from the attacker's side of the table. The
 * question is never "does the feature work" but "is the claim on the tin
 * actually true". Where a claim does NOT hold, the test pins the CURRENT
 * behaviour and says so in a `VULNERABILITY:` comment — so the suite stays
 * green while the gap stays visible and impossible to forget.
 */

function keypair(): { priv: string; pub: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    pub: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

function step(runId: string, index: number, payload: Record<string, unknown> = {}): Step {
  return withCommitments({
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
  }) as Step;
}

function run(id: string, steps: Step[]): Run {
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
  );
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
  it('an empty run verifies only with an empty anchor', () => {
    const empty: Run = { ...run('e', [step('e', 0)]), steps: [], runHash: '' };
    expect(verifyRun(empty).ok).toBe(true);
    // A fabricated anchor on a stepless run is rejected.
    const faked: Run = { ...empty, runHash: 'deadbeefdeadbeef' };
    expect(verifyRun(faked).ok).toBe(false);
    expect(verifyRun(faked).message).toContain('anchor was altered');
  });

  it('a single-step run anchors on that step’s hash', () => {
    const single = run('s', [step('s', 0)]);
    expect(verifyRun(single).ok).toBe(true);
    expect(single.runHash).toBe(single.steps[0]!.hash);
    // Editing the lone step breaks it at index 0.
    const broken: Run = { ...single, steps: [{ ...single.steps[0]!, label: 'rewritten' }] };
    expect(verifyRun(broken).ok).toBe(false);
    expect(verifyRun(broken).brokenStepIndex).toBe(0);
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

  it('VULNERABILITY: an UNSIGNED run can be truncated and still verifies', () => {
    /*
     * VULNERABILITY: the chain is a linked list with no commitment to its own
     * length or termination. Any PREFIX of a valid chain is itself a valid
     * chain, so dropping trailing steps and resetting runHash to the new last
     * hash produces a record that reports "chain intact".
     *
     * REAL-WORLD CONSEQUENCE: the most incriminating part of an agent run is
     * usually at the END (the destructive tool call, the error, the final
     * output). On an unsigned run an attacker deletes those steps and
     * `traceglass verify` still exits 0 saying the record was not modified.
     *
     * WHAT SHOULD HAPPEN: the anchor should commit to the step COUNT (e.g.
     * fold the length into the final hash), or unsigned runs should not be
     * reported as "intact" without that caveat.
     */
    const full = run('t', [step('t', 0), step('t', 1), step('t', 2)]);
    expect(verifyRun(full).ok).toBe(true);

    const truncated: Run = {
      ...full,
      steps: full.steps.slice(0, 2),
      runHash: full.steps[1]!.hash, // re-anchor on the new last step
    };
    const result = verifyRun(truncated);
    expect(result.ok).toBe(true); // <-- THE HOLE
    expect(result.message).toContain('chain intact');
    expect(truncated.steps).toHaveLength(2);
  });

  it('truncation IS caught once the run is signed', () => {
    // The signature covers the ORIGINAL anchor, so moving the anchor to the new
    // last step invalidates it. Signing is currently the only defence against
    // truncation — which is why the test above is scoped to unsigned runs.
    const keys = keypair();
    const signed = signRun(run('t', [step('t', 0), step('t', 1), step('t', 2)]), keys.priv, keys.pub);
    const truncated: Run = {
      ...signed,
      steps: signed.steps.slice(0, 2),
      runHash: signed.steps[1]!.hash,
    };
    const result = verifyRunFull(truncated);
    expect(result.chain.ok).toBe(true); // chain still fooled
    expect(result.signature.ok).toBe(false); // signature is not
    expect(result.ok).toBe(false);
  });

  it('appending a fabricated step to a signed run is caught', () => {
    const keys = keypair();
    const signed = signRun(run('a', [step('a', 0)]), keys.priv, keys.pub);
    const extra = step('a', 1, { output: { exonerating: true } });
    const chainedExtra: Step = {
      ...extra,
      prevHash: signed.steps[0]!.hash,
      hash: hashStep({ ...extra, prevHash: signed.steps[0]!.hash }, signed.steps[0]!.hash),
    };
    const extended: Run = {
      ...signed,
      steps: [...signed.steps, chainedExtra],
      runHash: chainedExtra.hash,
    };
    const result = verifyRunFull(extended);
    expect(result.chain.ok).toBe(true);
    expect(result.signature.ok).toBe(false);
    expect(result.ok).toBe(false);
  });
});
