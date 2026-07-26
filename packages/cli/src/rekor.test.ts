import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  buildHashedRekord,
  leafHash,
  nodeHash,
  parseRekorResponse,
  rootFromInclusionProof,
  setPayload,
  verifyRekorProof,
  type RekorEntry,
} from './rekor.js';

/**
 * Rekor anchoring — all offline.
 *
 * The Merkle code is cross-checked against a SECOND, independent
 * implementation written below straight from the recursive definitions in
 * RFC 9162 §2.1.1 and §2.1.3.1. The verifier in rekor.ts uses the iterative
 * §2.1.3.2 algorithm instead, so agreement between them is real evidence and
 * not a tautology.
 *
 * HONEST LIMIT — see the summary in the README: nothing here proves our request
 * shape or SET payload construction match what a live Rekor instance produces.
 * That was not reachable from this environment and is explicitly unverified.
 */

/* ---- Independent reference implementation (RFC 9162 §2.1.1, §2.1.3.1) ----- */

/** Largest power of two strictly smaller than n. */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH(D[n]) — the recursive Merkle Tree Hash. */
function referenceRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return createHash('sha256').digest();
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(referenceRoot(leaves.slice(0, k)), referenceRoot(leaves.slice(k)));
}

/** PATH(m, D[n]) — the recursive inclusion path. */
function referencePath(m: number, leaves: Buffer[]): Buffer[] {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  return m < k
    ? [...referencePath(m, leaves.slice(0, k)), referenceRoot(leaves.slice(k))]
    : [...referencePath(m - k, leaves.slice(k)), referenceRoot(leaves.slice(0, k))];
}

/* -------------------------------- helpers --------------------------------- */

const logKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const signerKeys = generateKeyPairSync('ed25519');
const signerPublicPem = signerKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();

const statement = Buffer.from('traceglass anchor statement for run acme-1', 'utf8');
const digestHex = createHash('sha256').update(statement).digest('hex');
const statementSig = sign(null, statement, signerKeys.privateKey).toString('base64');

/** Build a Rekor-shaped log with our entry at `index` among `total` leaves. */
function buildLog(index: number, total: number) {
  const body = Buffer.from(
    JSON.stringify(buildHashedRekord(digestHex, statementSig, signerPublicPem)),
    'utf8',
  );
  const leaves: Buffer[] = [];
  for (let i = 0; i < total; i++) {
    leaves.push(i === index ? body : Buffer.from(`unrelated log entry #${i}`, 'utf8'));
  }
  return {
    body,
    rootHash: referenceRoot(leaves).toString('hex'),
    hashes: referencePath(index, leaves).map((h) => h.toString('hex')),
    treeSize: total,
    index,
  };
}

/** A full, signed entry as Rekor would return it. */
function buildEntry(index = 5, total = 11): RekorEntry {
  const log = buildLog(index, total);
  const entry: RekorEntry = {
    uuid: '24296fb24b8ad77a'.repeat(4),
    body: log.body.toString('base64'),
    integratedTime: 1785000000,
    logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
    logIndex: 9_000_001,
    inclusionProof: {
      logIndex: log.index,
      rootHash: log.rootHash,
      treeSize: log.treeSize,
      hashes: log.hashes,
    },
  };
  entry.signedEntryTimestamp = sign('sha256', setPayload(entry), logKeys.privateKey).toString(
    'base64',
  );
  return entry;
}

const logKeyPem = logKeys.publicKey.export({ type: 'spki', format: 'pem' }).toString();

/* --------------------------------- tests ---------------------------------- */

describe('Merkle inclusion proofs (RFC 9162)', () => {
  it('agrees with the independent recursive reference for every leaf of many tree sizes', () => {
    let checked = 0;
    for (const total of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 32, 33]) {
      const leaves = Array.from({ length: total }, (_, i) => Buffer.from(`leaf-${i}`));
      const root = referenceRoot(leaves);
      for (let i = 0; i < total; i++) {
        const path = referencePath(i, leaves);
        const recomputed = rootFromInclusionProof(leafHash(leaves[i]!), i, total, path);
        expect(recomputed.equals(root), `tree ${total}, leaf ${i}`).toBe(true);
        checked++;
      }
    }
    expect(checked).toBe(168);
  });

  it('rejects a proof for the wrong leaf index', () => {
    const leaves = Array.from({ length: 9 }, (_, i) => Buffer.from(`leaf-${i}`));
    const root = referenceRoot(leaves);
    const path = referencePath(3, leaves);
    const recomputed = rootFromInclusionProof(leafHash(leaves[3]!), 4, 9, path);
    expect(recomputed.equals(root)).toBe(false);
  });

  it('rejects out-of-range, truncated and over-long proofs', () => {
    const leaves = Array.from({ length: 8 }, (_, i) => Buffer.from(`leaf-${i}`));
    const path = referencePath(2, leaves);
    expect(() => rootFromInclusionProof(leafHash(leaves[2]!), 8, 8, path)).toThrow(/out of range/);
    expect(() => rootFromInclusionProof(leafHash(leaves[2]!), 2, 0, path)).toThrow(/out of range/);
    expect(() => rootFromInclusionProof(leafHash(leaves[2]!), 2, 8, path.slice(1))).toThrow(
      /shorter than/,
    );
    expect(() =>
      rootFromInclusionProof(leafHash(leaves[2]!), 2, 8, [...path, Buffer.alloc(32)]),
    ).toThrow(/longer than/);
    expect(() => rootFromInclusionProof(leafHash(leaves[2]!), 2, 8, [Buffer.alloc(5)])).toThrow(
      /32-byte/,
    );
  });

  it('domain-separates leaves from interior nodes', () => {
    // Without the 0x00/0x01 prefixes an attacker could present an interior node
    // as a leaf and forge inclusion of data that was never logged.
    const data = Buffer.from('x');
    expect(leafHash(data).equals(createHash('sha256').update(data).digest())).toBe(false);
    expect(nodeHash(data, data).equals(leafHash(Buffer.concat([data, data])))).toBe(false);
  });
});

describe('Rekor response parsing', () => {
  it('normalizes the uuid-keyed map the API returns', () => {
    const entry = buildEntry();
    const parsed = parseRekorResponse({
      [entry.uuid]: {
        body: entry.body,
        integratedTime: entry.integratedTime,
        logID: entry.logID,
        logIndex: entry.logIndex,
        verification: {
          inclusionProof: entry.inclusionProof,
          signedEntryTimestamp: entry.signedEntryTimestamp,
        },
      },
    });
    expect(parsed.uuid).toBe(entry.uuid);
    expect(parsed.logIndex).toBe(entry.logIndex);
    expect(parsed.inclusionProof?.treeSize).toBe(entry.inclusionProof!.treeSize);
    expect(parsed.signedEntryTimestamp).toBe(entry.signedEntryTimestamp);
  });

  it('refuses responses that are missing required fields', () => {
    expect(() => parseRekorResponse({})).toThrow(/expected exactly 1/);
    expect(() => parseRekorResponse({ a: {}, b: {} })).toThrow(/expected exactly 1/);
    expect(() => parseRekorResponse({ a: { body: 'x' } })).toThrow(/logIndex/);
    expect(() => parseRekorResponse(null)).toThrow(/not an object/);
  });
});

describe('Rekor proof verification', () => {
  it('accepts a well-formed entry with a valid SET', () => {
    const result = verifyRekorProof(buildEntry(), {
      expectedDigestHex: digestHex,
      logKeyPem,
      signedStatement: statement,
    });
    expect(result.problems).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.bindsExpectedDigest).toBe(true);
    expect(result.entrySignatureOk).toBe(true);
    expect(result.inclusionProofOk).toBe(true);
    expect(result.setVerified).toBe(true);
    expect(result.integratedTime).toBe('2026-07-25T17:20:00.000Z');
  });

  it('THE KEY CHECK: rejects a real log entry that is about a different run', () => {
    // An attacker's cheapest forgery is to point at a genuine, fully-valid
    // Rekor entry that has nothing to do with this record.
    const result = verifyRekorProof(buildEntry(), {
      expectedDigestHex: createHash('sha256').update('some other run').digest('hex'),
      logKeyPem,
      signedStatement: statement,
    });
    expect(result.ok).toBe(false);
    expect(result.bindsExpectedDigest).toBe(false);
    expect(result.problems.join(' ')).toMatch(/not about this run/);
  });

  it('rejects a tampered inclusion proof', () => {
    const entry = buildEntry();
    const hashes = [...entry.inclusionProof!.hashes];
    hashes[0] = 'a'.repeat(64);
    const result = verifyRekorProof(
      { ...entry, inclusionProof: { ...entry.inclusionProof!, hashes } },
      { expectedDigestHex: digestHex, logKeyPem, signedStatement: statement },
    );
    expect(result.ok).toBe(false);
    expect(result.inclusionProofOk).toBe(false);
    expect(result.problems.join(' ')).toMatch(/does not reach the stored root/);
  });

  it('rejects a SET signed by a key other than the log key', () => {
    const impostor = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const entry = buildEntry();
    entry.signedEntryTimestamp = sign('sha256', setPayload(entry), impostor.privateKey).toString(
      'base64',
    );
    const result = verifyRekorProof(entry, {
      expectedDigestHex: digestHex,
      logKeyPem,
      signedStatement: statement,
    });
    expect(result.ok).toBe(false);
    expect(result.setVerified).toBe(false);
    expect(result.problems.join(' ')).toMatch(/signed entry timestamp is INVALID/);
  });

  it('detects a SET replayed onto a different logIndex', () => {
    const entry = buildEntry();
    const result = verifyRekorProof(
      { ...entry, logIndex: entry.logIndex + 1 },
      { expectedDigestHex: digestHex, logKeyPem, signedStatement: statement },
    );
    expect(result.ok).toBe(false);
    expect(result.setVerified).toBe(false);
  });

  it('rejects an entry whose signature does not cover the anchor statement', () => {
    const result = verifyRekorProof(buildEntry(), {
      expectedDigestHex: digestHex,
      logKeyPem,
      signedStatement: Buffer.from('a different statement'),
    });
    expect(result.ok).toBe(false);
    expect(result.entrySignatureOk).toBe(false);
  });

  it('reports setVerified=null — never ok — when no log key is supplied', () => {
    /*
     * This is the honesty gate. Without Rekor's public key the inclusion proof
     * is self-referential: an attacker fabricates the entry AND a matching
     * root. It must never read as a clean pass.
     */
    const result = verifyRekorProof(buildEntry(), {
      expectedDigestHex: digestHex,
      signedStatement: statement,
    });
    expect(result.setVerified).toBeNull();
    expect(result.bindsExpectedDigest).toBe(true);
    expect(result.inclusionProofOk).toBe(true);
    expect(result.ok).toBe(false); // <-- not proven to be in the public log
  });

  it('treats malformed and hostile entries as failures, never exceptions', () => {
    const base = buildEntry();
    const cases: RekorEntry[] = [
      { ...base, body: 'not base64 json!!' },
      { ...base, body: Buffer.from('{"kind":"rekord"}').toString('base64') },
      { ...base, body: Buffer.from('[]').toString('base64') },
      { ...base, inclusionProof: { ...base.inclusionProof!, treeSize: -1 } },
      { ...base, inclusionProof: { ...base.inclusionProof!, hashes: ['zz'] } },
      { ...base, signedEntryTimestamp: 'not-a-signature' },
    ];
    for (const entry of cases) {
      const result = verifyRekorProof(entry, {
        expectedDigestHex: digestHex,
        logKeyPem,
        signedStatement: statement,
      });
      expect(result.ok).toBe(false);
      expect(result.problems.length).toBeGreaterThan(0);
    }
  });
});

describe('what we actually transmit', () => {
  it('sends only a digest, a signature and a public key — no run content', () => {
    const proposal = JSON.stringify(buildHashedRekord(digestHex, statementSig, signerPublicPem));
    expect(proposal).toContain(digestHex);
    // Nothing identifying about the run may appear in the submission.
    expect(proposal).not.toContain('acme-1');
    expect(proposal).not.toContain('traceglass anchor statement');
    const parsed = JSON.parse(proposal) as { kind: string; spec: Record<string, unknown> };
    expect(parsed.kind).toBe('hashedrekord');
    expect(Object.keys(parsed.spec).sort()).toEqual(['data', 'signature']);
  });
});
