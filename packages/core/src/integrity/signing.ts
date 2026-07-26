import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import type { RedactionRecord, Run, RunRedactionSeal, RunSignature } from '../model.js';
import { canonicalize, hashVersionOf } from './hash.js';
import { verifyRun, type VerifyResult } from './verify.js';

/**
 * Ed25519 signing of the run's integrity anchor.
 *
 * The hash chain proves internal consistency, but anyone who can edit the
 * store can also re-chain. A detached signature over the anchor, made with a
 * key the store never needs, is what upgrades "consistent" to "authentic":
 * re-chaining without the private key invalidates the signature.
 *
 * In `hashVersion: 2` the anchor covers the run's metadata too (see
 * computeRunHash), so this same signature now also binds `currency`, `status`,
 * `totals`, `name` and the timestamps. Nothing about the signing procedure
 * changed — the thing being signed got bigger.
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

/* ── redaction seal (hashVersion 2) ────────────────────────────────────────── */

const REDACT_TAG_V2 = `tgredact/2${String.fromCharCode(0)}`;

/** Every redaction entry in the run, in step order then log order. */
export function redactionLog(run: Run): Array<{ stepId: string; redactions: RedactionRecord[] }> {
  const out: Array<{ stepId: string; redactions: RedactionRecord[] }> = [];
  for (const step of run.steps) {
    if (step.redactions && step.redactions.length > 0) {
      out.push({ stepId: step.id, redactions: step.redactions });
    }
  }
  return out;
}

/**
 * Hash over the run's whole redaction log.
 *
 * Deleting an entry, adding one, changing a reason or moving one to a different
 * step all move this hash — which is the point: the seal below binds it.
 */
export function redactionsHash(run: Run): string {
  return createHash('sha256')
    .update(REDACT_TAG_V2 + canonicalize(redactionLog(run)))
    .digest('hex');
}

/** The exact byte string a redaction seal signs. */
export function redactionSealPayload(
  runId: string,
  runHash: string,
  hash: string,
  sealedAt: string,
): string {
  return canonicalize({ runId, runHash, redactionsHash: hash, sealedAt });
}

/**
 * Attest to the run's current redaction log.
 *
 * This is a SECOND signature, deliberately separate from `run.signature`: the
 * anchor signature was made before the redaction and must survive it untouched
 * (that is the whole property that makes GDPR erasure compatible with an audit
 * record). The seal binds the anchor as well, so it cannot be lifted onto a
 * different run, and `sealedAt` records when the redaction was vouched for.
 */
export function sealRedactions(run: Run, privateKeyPem: string, publicKeyPem: string): Run {
  if (hashVersionOf(run) !== 2) {
    throw new Error(
      'Redaction seals are a hashVersion 2 feature; this record declares version ' +
        `${hashVersionOf(run)}. Re-record it under the current format to seal redactions.`,
    );
  }
  const sealedAt = new Date().toISOString();
  const hash = redactionsHash(run);
  const payload = Buffer.from(
    redactionSealPayload(run.id, run.runHash, hash, sealedAt),
    'utf8',
  );
  const redactionSeal: RunRedactionSeal = {
    algorithm: 'ed25519',
    keyId: keyIdFromPublicKey(publicKeyPem),
    publicKey: publicKeyPem,
    signature: sign(null, payload, createPrivateKey(privateKeyPem)).toString('base64'),
    sealedAt,
    redactionsHash: hash,
  };
  return { ...run, redactionSeal };
}

export interface RedactionVerifyResult {
  /** False only when a seal is PRESENT and does not hold. */
  ok: boolean;
  /** True when a valid seal covers this exact redaction log. */
  attested: boolean;
  /** keyId of the seal, when there is one. */
  keyId: string | null;
  /** Every redacted path in the run, as `<stepId>#<path>`. */
  paths: string[];
  message: string;
}

/**
 * Check the redaction seal, if any.
 *
 * Three outcomes an auditor must be able to tell apart, and which
 * `verifyRunFull` surfaces separately rather than folding into a boolean:
 *
 *   - no redactions at all;
 *   - redactions DECLARED but unattested — the record admits data was
 *     destroyed, but only the last writer of the file says so. Version 2's
 *     commitment rule (see verifyCommitments) already guarantees the
 *     declaration exists, so this is never SILENT erasure;
 *   - redactions attested by a keyholder — fabricating, deleting or editing an
 *     entry, or stripping the seal, all break this and none are possible
 *     without the private key.
 */
export function verifyRedactionSeal(run: Run): RedactionVerifyResult {
  const paths = redactionLog(run).flatMap(({ stepId, redactions }) =>
    redactions.map((r) => `${stepId}#${r.path}`),
  );
  const seal = run.redactionSeal;

  if (!seal) {
    let message: string;
    if (paths.length === 0) message = 'No redactions recorded.';
    else if (hashVersionOf(run) !== 2) {
      message = `${paths.length} redaction(s) recorded; tgcanon/1 has no attestation mechanism, so nothing covers this log.`;
    } else {
      message = `${paths.length} redaction(s) recorded, UNATTESTED: no keyholder has sealed this redaction log, so the entries are a claim by whoever last wrote the file.`;
    }
    return { ok: true, attested: false, keyId: null, paths, message };
  }

  const expected = redactionsHash(run);
  if (seal.redactionsHash !== expected) {
    return {
      ok: false,
      attested: false,
      keyId: seal.keyId,
      paths,
      message: `Redaction seal INVALID (keyId ${seal.keyId}): the redaction log does not match the sealed digest — an entry was added, removed or edited after sealing.`,
    };
  }

  const payload = Buffer.from(
    redactionSealPayload(run.id, run.runHash, expected, seal.sealedAt),
    'utf8',
  );
  let valid = false;
  try {
    valid = verify(null, payload, createPublicKey(seal.publicKey), Buffer.from(seal.signature, 'base64'));
  } catch {
    valid = false;
  }
  if (!valid) {
    return {
      ok: false,
      attested: false,
      keyId: seal.keyId,
      paths,
      message: `Redaction seal INVALID (keyId ${seal.keyId}): the seal was not made by this key, or the record changed after sealing.`,
    };
  }
  return {
    ok: true,
    attested: true,
    keyId: seal.keyId,
    paths,
    message: `Redaction seal OK (keyId ${seal.keyId}): ${paths.length} redaction(s) attested at ${seal.sealedAt}.`,
  };
}

export interface FullVerifyResult {
  chain: VerifyResult;
  signature: SignatureVerifyResult;
  /** Redaction-log attestation (`hashVersion: 2`); inert on version-1 records. */
  redaction: RedactionVerifyResult;
  /** True only when the chain is intact AND any present signature/seal is valid. */
  ok: boolean;
}

/** Chain + signature + redaction-seal verification in one call. */
export function verifyRunFull(run: Run): FullVerifyResult {
  const chain = verifyRun(run);
  const signature = verifySignature(run);
  const redaction = verifyRedactionSeal(run);
  return { chain, signature, redaction, ok: chain.ok && signature.ok && redaction.ok };
}
