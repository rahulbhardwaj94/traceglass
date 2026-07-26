import { createHash, createPublicKey, verify } from 'node:crypto';

/**
 * Sigstore / Rekor transparency-log anchoring.
 *
 * Rekor is an append-only Merkle log. Appending an anchor turns "this record
 * was deleted" into "this record is missing from a sequence", which — unlike
 * deletion from a local file — is detectable by a third party
 * (docs/threat-model.md §3.5).
 *
 * WHAT WE SUBMIT, EXACTLY
 * -----------------------
 * A `hashedrekord` entry, which is the minimum-disclosure entry type: it
 * carries the SHA-256 *digest* of the anchor statement, never the statement
 * itself. Three things leave the machine and nothing else:
 *   - the digest (64 hex chars) — reveals nothing about the run's contents,
 *     but see the privacy note in the README: it does reveal that a record
 *     exists and when, to a permanent public log;
 *   - an Ed25519 signature over the anchor statement;
 *   - the operator's Ed25519 PUBLIC key, which links every entry made with it.
 * No payloads, step labels, tool names, costs or run ids are transmitted.
 *
 * WHAT CAN BE CHECKED OFFLINE AFTERWARDS — and what cannot
 * --------------------------------------------------------
 * Offline, from the stored proof alone, `verifyRekorProof` establishes:
 *   1. the log entry is about THIS run — the body's data hash equals the
 *      digest of the anchor statement we recompute locally;
 *   2. the entry's signature verifies under the embedded public key;
 *   3. the inclusion proof is arithmetically sound: the RFC 9162 leaf hash
 *      chains through the stored path to the stored root hash.
 *
 * Check 3 on its own proves nothing about the *public* log, because an
 * attacker who fabricates an entry can equally fabricate a consistent proof to
 * a root they invented. Only the Signed Entry Timestamp (SET), verified against
 * Rekor's own public key obtained out of band, binds the entry to the real log.
 * So `verifyRekorProof` reports `setVerified` separately and never lets an
 * unverified SET count as success-by-omission; `logKeyPem` is what upgrades the
 * claim. This mirrors the `certPinned` distinction in rfc3161.ts.
 */

/* -------------------------------------------------------------------------- */
/* Wire types                                                                  */
/* -------------------------------------------------------------------------- */

export interface RekorInclusionProof {
  logIndex: number;
  rootHash: string;
  treeSize: number;
  hashes: string[];
  checkpoint?: string;
}

/** The subset of a Rekor log entry we persist. */
export interface RekorEntry {
  uuid: string;
  /** base64 of the log's canonicalized entry body — the Merkle leaf preimage. */
  body: string;
  integratedTime: number;
  logID: string;
  logIndex: number;
  inclusionProof?: RekorInclusionProof;
  signedEntryTimestamp?: string;
}

/** Build the `hashedrekord` proposal Rekor expects on POST. */
export function buildHashedRekord(
  digestHex: string,
  signatureBase64: string,
  publicKeyPem: string,
): unknown {
  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: { hash: { algorithm: 'sha256', value: digestHex } },
      signature: {
        content: signatureBase64,
        publicKey: { content: Buffer.from(publicKeyPem, 'utf8').toString('base64') },
      },
    },
  };
}

/**
 * Normalize the `POST /api/v1/log/entries` response, which is a single-key map
 * of uuid -> entry.
 */
export function parseRekorResponse(json: unknown): RekorEntry {
  if (!json || typeof json !== 'object') throw new Error('Rekor response is not an object');
  const entries = Object.entries(json as Record<string, unknown>);
  if (entries.length !== 1) {
    throw new Error(`Rekor response has ${entries.length} entries; expected exactly 1`);
  }
  const [uuid, raw] = entries[0]!;
  if (!raw || typeof raw !== 'object') throw new Error('Rekor entry is not an object');
  const entry = raw as Record<string, unknown>;

  const body = entry.body;
  if (typeof body !== 'string') throw new Error('Rekor entry has no body');
  const logIndex = entry.logIndex;
  const integratedTime = entry.integratedTime;
  const logID = entry.logID;
  if (typeof logIndex !== 'number') throw new Error('Rekor entry has no logIndex');
  if (typeof integratedTime !== 'number') throw new Error('Rekor entry has no integratedTime');
  if (typeof logID !== 'string') throw new Error('Rekor entry has no logID');

  const verification = (entry.verification ?? {}) as Record<string, unknown>;
  const rawProof = verification.inclusionProof as Record<string, unknown> | undefined;
  let inclusionProof: RekorInclusionProof | undefined;
  if (rawProof) {
    const hashes = Array.isArray(rawProof.hashes) ? rawProof.hashes.filter(isHex) : [];
    if (
      typeof rawProof.logIndex === 'number' &&
      typeof rawProof.treeSize === 'number' &&
      isHex(rawProof.rootHash)
    ) {
      inclusionProof = {
        logIndex: rawProof.logIndex,
        treeSize: rawProof.treeSize,
        rootHash: rawProof.rootHash,
        hashes,
        ...(typeof rawProof.checkpoint === 'string' ? { checkpoint: rawProof.checkpoint } : {}),
      };
    }
  }

  return {
    uuid,
    body,
    integratedTime,
    logID,
    logIndex,
    ...(inclusionProof ? { inclusionProof } : {}),
    ...(typeof verification.signedEntryTimestamp === 'string'
      ? { signedEntryTimestamp: verification.signedEntryTimestamp }
      : {}),
  };
}

function isHex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]*$/i.test(value) && value.length % 2 === 0;
}

/* -------------------------------------------------------------------------- */
/* Merkle inclusion proof (RFC 9162 §2.1.3)                                    */
/* -------------------------------------------------------------------------- */

/** Leaf hash: HASH(0x00 || entry). The 0x00 prefix is the domain separator. */
export function leafHash(entry: Buffer): Buffer {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), entry]))
    .digest();
}

/** Interior node: HASH(0x01 || left || right). */
export function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x01]), left, right]))
    .digest();
}

/**
 * Recompute the Merkle root from a leaf and its inclusion path, per the
 * verification algorithm in RFC 9162 §2.1.3.2. Throws on a malformed proof.
 */
export function rootFromInclusionProof(
  leaf: Buffer,
  leafIndex: number,
  treeSize: number,
  path: Buffer[],
): Buffer {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize)) {
    throw new Error('inclusion proof: leafIndex and treeSize must be integers');
  }
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) {
    throw new Error(
      `inclusion proof: leafIndex ${leafIndex} out of range for treeSize ${treeSize}`,
    );
  }

  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leaf;

  for (const p of path) {
    if (p.length !== 32) throw new Error('inclusion proof: path node is not a 32-byte hash');
    if (sn === 0) throw new Error('inclusion proof: path is longer than the tree is deep');
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        // fn === sn and fn is even: climb past the run of right-edge nodes.
        while (fn !== 0 && fn % 2 === 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  if (sn !== 0) throw new Error('inclusion proof: path is shorter than the tree is deep');
  return r;
}

/* -------------------------------------------------------------------------- */
/* Signed Entry Timestamp                                                      */
/* -------------------------------------------------------------------------- */

/**
 * The exact bytes Rekor signs for the SET: canonical JSON over four fields,
 * keys sorted (they already are in this order), no whitespace.
 */
export function setPayload(entry: RekorEntry): Buffer {
  const canonical =
    '{"body":' +
    JSON.stringify(entry.body) +
    ',"integratedTime":' +
    String(entry.integratedTime) +
    ',"logID":' +
    JSON.stringify(entry.logID) +
    ',"logIndex":' +
    String(entry.logIndex) +
    '}';
  return Buffer.from(canonical, 'utf8');
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

export interface RekorVerification {
  ok: boolean;
  /** The entry body's data hash equals the digest we expected. */
  bindsExpectedDigest: boolean;
  /** The entry's own signature verifies under the public key it embeds. */
  entrySignatureOk: boolean;
  /** The inclusion path recomputes the stored root hash. */
  inclusionProofOk: boolean | null;
  /**
   * The SET verified against a log key supplied out of band.
   * FALSE OR NULL MEANS THE ENTRY IS NOT PROVEN TO BE IN THE PUBLIC LOG.
   */
  setVerified: boolean | null;
  /** keyId-style fingerprint of the key that signed the entry. */
  publicKeyPem: string | null;
  integratedTime: string | null;
  problems: string[];
}

export interface VerifyRekorOptions {
  expectedDigestHex: string;
  /** Rekor's public key (PEM), obtained out of band. Without it the SET is unchecked. */
  logKeyPem?: string | undefined;
  /** The signed statement bytes, so the entry signature can be re-verified. */
  signedStatement?: Buffer | undefined;
}

/**
 * Verify a stored Rekor proof offline. Like the RFC 3161 verifier, this never
 * throws on malformed input: the bytes come from a file an attacker may have
 * written, so a parse failure is a verification failure with a reason.
 */
export function verifyRekorProof(entry: RekorEntry, opts: VerifyRekorOptions): RekorVerification {
  const problems: string[] = [];
  let bindsExpectedDigest = false;
  let entrySignatureOk = false;
  let inclusionProofOk: boolean | null = null;
  let setVerified: boolean | null = null;
  let publicKeyPem: string | null = null;

  // 1. Decode the body and confirm the entry is about our digest.
  let bodyBytes: Buffer;
  let body: Record<string, unknown>;
  try {
    bodyBytes = Buffer.from(entry.body, 'base64');
    body = JSON.parse(bodyBytes.toString('utf8')) as Record<string, unknown>;
  } catch (e) {
    problems.push(`entry body is not decodable JSON: ${describe(e)}`);
    return {
      ok: false,
      bindsExpectedDigest: false,
      entrySignatureOk: false,
      inclusionProofOk: null,
      setVerified: null,
      publicKeyPem: null,
      integratedTime: null,
      problems,
    };
  }

  if (body.kind !== 'hashedrekord') {
    problems.push(`unexpected entry kind "${String(body.kind)}" (expected hashedrekord)`);
  }
  const spec = (body.spec ?? {}) as Record<string, unknown>;
  const data = (spec.data ?? {}) as Record<string, unknown>;
  const hash = (data.hash ?? {}) as Record<string, unknown>;
  const loggedDigest = typeof hash.value === 'string' ? hash.value.toLowerCase() : '';
  const expected = opts.expectedDigestHex.toLowerCase();

  bindsExpectedDigest = loggedDigest.length > 0 && loggedDigest === expected;
  if (!bindsExpectedDigest) {
    problems.push(
      `the log entry is not about this run: entry covers ${loggedDigest || '(none)'}, expected ${expected}`,
    );
  }
  if (hash.algorithm !== undefined && hash.algorithm !== 'sha256') {
    const named = typeof hash.algorithm === 'string' ? hash.algorithm : '(not a string)';
    problems.push(`entry uses hash algorithm "${named}" (expected sha256)`);
  }

  // 2. The entry's own signature.
  const sigSpec = (spec.signature ?? {}) as Record<string, unknown>;
  const sigContent = typeof sigSpec.content === 'string' ? sigSpec.content : null;
  const keySpec = (sigSpec.publicKey ?? {}) as Record<string, unknown>;
  const keyContent = typeof keySpec.content === 'string' ? keySpec.content : null;

  if (!sigContent || !keyContent) {
    problems.push('entry carries no signature or no public key');
  } else {
    publicKeyPem = Buffer.from(keyContent, 'base64').toString('utf8');
    if (opts.signedStatement) {
      try {
        entrySignatureOk = verify(
          null,
          opts.signedStatement,
          createPublicKey(publicKeyPem),
          Buffer.from(sigContent, 'base64'),
        );
      } catch (e) {
        problems.push(`entry signature could not be checked: ${describe(e)}`);
      }
      if (!entrySignatureOk) {
        problems.push('the entry signature does not verify over the anchor statement');
      }
    } else {
      problems.push('no anchor statement available to re-verify the entry signature against');
    }
  }

  // 3. Inclusion proof arithmetic.
  if (entry.inclusionProof) {
    const proof = entry.inclusionProof;
    try {
      const recomputed = rootFromInclusionProof(
        leafHash(bodyBytes),
        proof.logIndex,
        proof.treeSize,
        proof.hashes.map((h) => Buffer.from(h, 'hex')),
      );
      inclusionProofOk = recomputed.toString('hex') === proof.rootHash.toLowerCase();
      if (!inclusionProofOk) {
        problems.push(
          `inclusion proof does not reach the stored root (computed ${recomputed.toString('hex')}, stored ${proof.rootHash})`,
        );
      }
    } catch (e) {
      inclusionProofOk = false;
      problems.push(`inclusion proof is malformed: ${describe(e)}`);
    }
  } else {
    problems.push('no inclusion proof stored with this entry');
  }

  // 4. The SET — the only check that ties any of this to the real public log.
  if (entry.signedEntryTimestamp) {
    if (opts.logKeyPem) {
      try {
        setVerified = verify(
          'sha256',
          setPayload(entry),
          createPublicKey(opts.logKeyPem),
          Buffer.from(entry.signedEntryTimestamp, 'base64'),
        );
      } catch (e) {
        setVerified = false;
        problems.push(`signed entry timestamp could not be checked: ${describe(e)}`);
      }
      if (setVerified === false) {
        problems.push('the signed entry timestamp is INVALID under the supplied log key');
      }
    }
  } else {
    problems.push('no signed entry timestamp stored, so log membership cannot be proven');
  }

  // `ok` means FULLY PROVEN, so an unchecked SET (null) must not pass. Without
  // the log's key the inclusion proof is self-referential — an attacker who
  // fabricates the entry fabricates a matching root too. Callers that want to
  // report the weaker "self-consistent" state must read the fields, not `ok`.
  const ok =
    problems.length === 0 &&
    bindsExpectedDigest &&
    entrySignatureOk &&
    inclusionProofOk === true &&
    setVerified === true;

  return {
    ok,
    bindsExpectedDigest,
    entrySignatureOk,
    inclusionProofOk,
    setVerified,
    publicKeyPem,
    integratedTime: Number.isFinite(entry.integratedTime)
      ? new Date(entry.integratedTime * 1000).toISOString()
      : null,
    problems,
  };
}

/* -------------------------------------------------------------------------- */
/* Network                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * POST an entry to a Rekor instance. The only network call in this module, and
 * unreachable unless the operator passed an explicit `--rekor <url>`.
 *
 * NOTE — submitting to a PUBLIC log is irreversible: Rekor is append-only by
 * design and entries cannot be retracted. The CLI requires `--i-understand-
 * public-log` before calling this, because "I did not realise it was permanent"
 * is not a recoverable mistake.
 */
export async function submitEntry(
  rekorUrl: string,
  proposal: unknown,
  opts: { timeoutMs?: number } = {},
): Promise<RekorEntry> {
  const url = `${rekorUrl.replace(/\/+$/, '')}/api/v1/log/entries`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  let res: Response;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(proposal),
      signal: controller.signal,
    });
  } catch (e) {
    const reason = e instanceof Error && e.name === 'AbortError' ? 'timed out' : describe(e);
    throw new Error(`Rekor request to ${url} failed: ${reason}`);
  } finally {
    clearTimeout(timeout);
  }

  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `Rekor ${url} returned HTTP ${res.status} ${res.statusText}${text ? `: ${text.slice(0, 300)}` : ''}`,
    );
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Rekor ${url} returned a non-JSON response`);
  }
  return parseRekorResponse(json);
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
