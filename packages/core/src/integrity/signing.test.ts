import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import type { Run } from '../model.js';
import { applyHashChain } from './hash.js';
import { keyIdFromPublicKey, signRun, verifyRunFull, verifySignature } from './signing.js';

function pems() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

function makeRun(id: string): Run {
  const base: Run = {
    id,
    name: 'test run',
    startedAt: '2026-01-01T00:00:00.000Z',
    endedAt: '2026-01-01T00:00:01.000Z',
    status: 'completed',
    currency: 'USD',
    totals: { tokens: 10, cost: 0.5, durationMs: 1000, steps: 2 },
    warnings: [],
    steps: [0, 1].map((index) => ({
      id: `${id}:${index}`,
      runId: id,
      index,
      type: index === 0 ? ('user_input' as const) : ('final_output' as const),
      label: `step ${index}`,
      startedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 500,
      tokens: 5,
      cost: 0.25,
      spanId: `span-${index}`,
      hash: '',
      prevHash: '',
    })),
    runHash: '',
  };
  return applyHashChain(base);
}

describe('signing', () => {
  it('sign → verify roundtrip passes chain and signature', () => {
    const { privateKeyPem, publicKeyPem } = pems();
    const signed = signRun(makeRun('r1'), privateKeyPem, publicKeyPem);
    const result = verifyRunFull(signed);
    expect(result.ok).toBe(true);
    expect(result.signature.keyId).toBe(keyIdFromPublicKey(publicKeyPem));
  });

  it('unsigned run verifies as unsigned, not as a failure', () => {
    const result = verifyRunFull(makeRun('r2'));
    expect(result.ok).toBe(true);
    expect(result.signature.keyId).toBeNull();
    expect(result.signature.message).toContain('unsigned');
  });

  it('tampering with a step after signing fails the chain', () => {
    const { privateKeyPem, publicKeyPem } = pems();
    const signed = signRun(makeRun('r3'), privateKeyPem, publicKeyPem);
    const tampered: Run = {
      ...signed,
      steps: signed.steps.map((s, i) => (i === 1 ? { ...s, cost: 999 } : s)),
    };
    const result = verifyRunFull(tampered);
    expect(result.ok).toBe(false);
    expect(result.chain.ok).toBe(false);
    expect(result.chain.brokenStepIndex).toBe(1);
  });

  it('re-chaining a tampered run is caught by the signature', () => {
    const { privateKeyPem, publicKeyPem } = pems();
    const signed = signRun(makeRun('r4'), privateKeyPem, publicKeyPem);
    // Attacker edits a step AND recomputes the whole chain (no private key).
    const rechained = applyHashChain({
      ...signed,
      steps: signed.steps.map((s, i) => (i === 0 ? { ...s, label: 'edited' } : s)),
    });
    const result = verifyRunFull(rechained);
    expect(result.chain.ok).toBe(true); // chain alone is fooled
    expect(result.signature.ok).toBe(false); // signature is not
    expect(result.ok).toBe(false);
  });

  it('a signature transplanted from another run fails', () => {
    const { privateKeyPem, publicKeyPem } = pems();
    const signedA = signRun(makeRun('a'), privateKeyPem, publicKeyPem);
    const runB = makeRun('b');
    const transplanted: Run = { ...runB, signature: signedA.signature };
    expect(verifySignature(transplanted).ok).toBe(false);
  });

  it('refuses to sign an unfinalized run', () => {
    const { privateKeyPem, publicKeyPem } = pems();
    const raw = { ...makeRun('r5'), runHash: '' };
    expect(() => signRun(raw, privateKeyPem, publicKeyPem)).toThrow(/runHash/);
  });

  it('garbage signature bytes fail cleanly', () => {
    const { privateKeyPem, publicKeyPem } = pems();
    const signed = signRun(makeRun('r6'), privateKeyPem, publicKeyPem);
    const broken: Run = {
      ...signed,
      signature: { ...signed.signature!, signature: 'bm90LWEtc2ln' },
    };
    expect(verifySignature(broken).ok).toBe(false);
  });
});
