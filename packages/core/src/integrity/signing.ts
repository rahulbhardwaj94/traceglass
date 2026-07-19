import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { Run, RunSignature } from '../model.js';
import { canonicalize } from './hash.js';
import { verifyRun, type VerifyResult } from './verify.js';

/**
 * Ed25519 signing of the run's integrity anchor.
 *
 * The hash chain proves internal consistency, but anyone who can edit the
 * store can also re-chain. A detached signature over the anchor, made with a
 * key the store never needs, is what upgrades "consistent" to "authentic":
 * re-chaining without the private key invalidates the signature.
 */

/** The exact byte string that gets signed. */
export function signaturePayload(runId: string, runHash: string, signedAt: string): string {
  return canonicalize({ runId, runHash, signedAt });
}

/** Short stable identifier for a public key: first 16 hex of sha256(SPKI DER). */
export function keyIdFromPublicKey(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/** Return a copy of the run carrying a fresh signature over its runHash. */
export function signRun(run: Run, privateKeyPem: string, publicKeyPem: string): Run {
  if (!run.runHash) {
    throw new Error('Cannot sign a run without a runHash — finalize it first.');
  }
  const signedAt = new Date().toISOString();
  const payload = Buffer.from(signaturePayload(run.id, run.runHash, signedAt), 'utf8');
  const signature: RunSignature = {
    algorithm: 'ed25519',
    keyId: keyIdFromPublicKey(publicKeyPem),
    publicKey: publicKeyPem,
    signature: sign(null, payload, createPrivateKey(privateKeyPem)).toString('base64'),
    signedAt,
  };
  return { ...run, signature };
}

export interface SignatureVerifyResult {
  ok: boolean;
  /** keyId of the signature checked; null when the run is unsigned. */
  keyId: string | null;
  message: string;
}

/**
 * Verify the run's signature against its stored runHash. An unsigned run is
 * not a failure (legacy records predate signing) — callers decide policy.
 * Note: only meaningful alongside a chain check; use verifyRunFull for both.
 */
export function verifySignature(run: Run): SignatureVerifyResult {
  const sig = run.signature;
  if (!sig) {
    return { ok: true, keyId: null, message: 'Run is unsigned.' };
  }
  const payload = Buffer.from(signaturePayload(run.id, run.runHash, sig.signedAt), 'utf8');
  let valid = false;
  try {
    valid = verify(
      null,
      payload,
      createPublicKey(sig.publicKey),
      Buffer.from(sig.signature, 'base64'),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    return {
      ok: false,
      keyId: sig.keyId,
      message: `Signature INVALID (keyId ${sig.keyId}): the anchor was not signed by this key, or the record changed after signing.`,
    };
  }
  return { ok: true, keyId: sig.keyId, message: `Signature OK (keyId ${sig.keyId}).` };
}

export interface FullVerifyResult {
  chain: VerifyResult;
  signature: SignatureVerifyResult;
  /** True only when the chain is intact AND any present signature is valid. */
  ok: boolean;
}

/** Chain + signature verification in one call. */
export function verifyRunFull(run: Run): FullVerifyResult {
  const chain = verifyRun(run);
  const signature = verifySignature(run);
  return { chain, signature, ok: chain.ok && signature.ok };
}
