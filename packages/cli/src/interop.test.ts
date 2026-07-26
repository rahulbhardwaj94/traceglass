import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Run } from '@traceglass/core';
import { parseTimeStampResponse, parseTimeStampToken, verifyTimeStampToken } from './rfc3161.js';
import { leafHash, parseRekorResponse, rootFromInclusionProof, setPayload } from './rekor.js';
import { anchorStatement, verifyRunAgainstAnchors, type AnchorRecord } from './anchors.js';

/**
 * INTEROP — real-world artefacts, checked offline.
 *
 * Everything in this file was captured from PRODUCTION services during
 * development and committed, so the suite proves interoperability while still
 * running with no network at all:
 *
 *   - `live-digicert-response.tsr` / `live-sectigo-response.tsr` — genuine
 *     RFC 3161 tokens issued by DigiCert's and Sectigo's public TSAs over this
 *     repo's canned anchor statement. Between them they exercise 3-certificate
 *     chains, bare `rsaEncryption` signature algorithms, and two different TSA
 *     policy OIDs — none of which our own OpenSSL fixture covers.
 *   - `rekor-entry.json` / `rekor-public-key.pem` — a real entry read back from
 *     the public Sigstore log (tree size ~2.1 billion), with its 31-node
 *     inclusion path, plus the log's real ECDSA P-256 public key.
 *
 * These are the tests that would have caught a subtly wrong Merkle computation
 * or SET canonicalization, which no amount of self-consistent synthetic data
 * can: a synthetic signer would simply share our mistake.
 *
 * To refresh them, re-run the capture scripts documented in
 * test-fixtures/README.md. They are NOT regenerated at test time.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-fixtures');
const read = (name: string) => readFileSync(join(FIXTURES, name));

const canned = JSON.parse(readFileSync(join(FIXTURES, 'anchor-run.json'), 'utf8')) as {
  runId: string;
  runHash: string;
  keyId: string;
  signature: string;
};
const cannedRun = {
  id: canned.runId,
  runHash: canned.runHash,
  signature: { keyId: canned.keyId, signature: canned.signature },
} as unknown as Run;

const statement = read('anchor-statement.bin');
const digest = createHash('sha256').update(statement).digest();

describe('RFC 3161 interop with commercial public TSAs', () => {
  const authorities = [
    { name: 'DigiCert', file: 'live-digicert-response.tsr', nonce: 'live-digicert-nonce.txt' },
    { name: 'Sectigo', file: 'live-sectigo-response.tsr', nonce: 'live-sectigo-nonce.txt' },
  ];

  for (const tsa of authorities) {
    describe(tsa.name, () => {
      const raw = read(tsa.file);
      const nonce = Buffer.from(readFileSync(join(FIXTURES, tsa.nonce), 'utf8').trim(), 'hex');
      const tokenDer = parseTimeStampResponse(raw).tokenDer!;

      it('verifies fully: signature, content digest, imprint and nonce', () => {
        const result = verifyTimeStampToken(tokenDer, {
          expectedDigest: digest,
          expectedNonce: nonce,
        });
        expect(result.problems).toEqual([]);
        expect(result.ok).toBe(true);
        expect(result.signatureOk).toBe(true);
        expect(result.contentDigestOk).toBe(true);
        expect(result.imprintOk).toBe(true);
        expect(result.nonceOk).toBe(true);
        expect(result.hasTimestampingEku).toBe(true);
        expect(result.certValidAtGenTime).toBe(true);
        expect(Number.isNaN(Date.parse(result.genTime))).toBe(false);
      });

      it('embeds a full certificate chain and selects the right signer from it', () => {
        // Real TSAs ship the leaf plus intermediates. Picking the wrong one
        // would make the signature check fail, so this exercises the
        // IssuerAndSerialNumber match rather than "just try the first cert".
        const parsed = parseTimeStampToken(tokenDer);
        expect(parsed.certificates.length).toBeGreaterThanOrEqual(2);
        const result = verifyTimeStampToken(tokenDer, { expectedDigest: digest });
        expect(result.signatureOk).toBe(true);
        expect(result.certFingerprint).toMatch(/^[0-9a-f]{64}$/);
      });

      it('anchors the canned run end to end, reported as self-attested without a pin', () => {
        const record: AnchorRecord = {
          version: 2,
          runId: canned.runId,
          runHash: canned.runHash,
          keyId: canned.keyId,
          signature: canned.signature,
          anchoredAt: '2026-07-25T00:00:00.000Z',
          proof: {
            type: 'rfc3161',
            token: tokenDer.toString('base64'),
            genTime: '2026-07-25T00:00:00.000Z',
            hashAlgorithm: 'sha256',
          },
        };
        const check = verifyRunAgainstAnchors(cannedRun, [record]);
        expect(check.ok).toBe(true);
        expect(check.strength).toBe('self-attested');
        expect(check.provenExistedBy).not.toBeNull();
      });

      it('reaches "external" strength once the real TSA certificate is pinned', () => {
        // Pin the exact certificate the authority signed with, extracted from
        // the token itself — this is what an operator would obtain out of band.
        const parsed = parseTimeStampToken(tokenDer);
        const unpinned = verifyTimeStampToken(tokenDer, { expectedDigest: digest });
        const signer = parsed.certificates.find(
          (c) => c.fingerprint256.replace(/:/g, '').toLowerCase() === unpinned.certFingerprint,
        );
        expect(signer).toBeDefined();

        const record: AnchorRecord = {
          version: 2,
          runId: canned.runId,
          runHash: canned.runHash,
          keyId: canned.keyId,
          signature: canned.signature,
          anchoredAt: '2026-07-25T00:00:00.000Z',
          proof: {
            type: 'rfc3161',
            token: tokenDer.toString('base64'),
            genTime: '2026-07-25T00:00:00.000Z',
            hashAlgorithm: 'sha256',
          },
        };
        const check = verifyRunAgainstAnchors(cannedRun, [record], {
          tsaCertPem: signer!.toString(),
        });
        expect(check.problems).toEqual([]);
        expect(check.ok).toBe(true);
        expect(check.strength).toBe('external');
        expect(check.rfc3161?.certPinned).toBe(true);
      });

      it('rejects the real token when presented for a different run', () => {
        const otherRun = { ...cannedRun, id: 'not-the-anchored-run' } as Run;
        const record: AnchorRecord = {
          version: 2,
          runId: 'not-the-anchored-run',
          runHash: canned.runHash,
          keyId: canned.keyId,
          signature: canned.signature,
          anchoredAt: '2026-07-25T00:00:00.000Z',
          proof: {
            type: 'rfc3161',
            token: tokenDer.toString('base64'),
            genTime: '2026-07-25T00:00:00.000Z',
            hashAlgorithm: 'sha256',
          },
        };
        const check = verifyRunAgainstAnchors(otherRun, [record]);
        expect(check.ok).toBe(false);
        expect(check.rfc3161?.imprintOk).toBe(false);
      });
    });
  }

  it('the anchor statement the real TSAs signed is exactly what we recompute', () => {
    // If this drifts, every timestamp ever issued stops matching its run.
    expect(anchorStatement(cannedRun).equals(statement)).toBe(true);
  });
});

describe('Rekor interop with the public Sigstore log', () => {
  const entry = parseRekorResponse(
    JSON.parse(readFileSync(join(FIXTURES, 'rekor-entry.json'), 'utf8')),
  );
  const logKeyPem = readFileSync(join(FIXTURES, 'rekor-public-key.pem'), 'utf8');

  it('parses a real log entry', () => {
    expect(entry.logIndex).toBeGreaterThan(0);
    expect(entry.integratedTime).toBeGreaterThan(0);
    expect(entry.logID).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.inclusionProof).toBeDefined();
    expect(entry.signedEntryTimestamp).toBeTruthy();
  });

  it('recomputes the REAL Merkle root from a real 30+ node inclusion path', () => {
    /*
     * The strongest available evidence that the RFC 9162 implementation is
     * right: a genuine path from the public log, in a tree of billions of
     * entries, must reproduce the log's own published root hash exactly. An
     * off-by-one in the fn/sn shifting would fail here and nowhere else.
     */
    const proof = entry.inclusionProof!;
    expect(proof.hashes.length).toBeGreaterThan(20);
    expect(proof.treeSize).toBeGreaterThan(1_000_000);

    const root = rootFromInclusionProof(
      leafHash(Buffer.from(entry.body, 'base64')),
      proof.logIndex,
      proof.treeSize,
      proof.hashes.map((h) => Buffer.from(h, 'hex')),
    );
    expect(root.toString('hex')).toBe(proof.rootHash.toLowerCase());
  });

  it('rejects the real proof if the leaf is altered by one byte', () => {
    const proof = entry.inclusionProof!;
    const body = Buffer.from(entry.body, 'base64');
    body[body.length - 1] = body[body.length - 1]! ^ 0x01;
    const root = rootFromInclusionProof(
      leafHash(body),
      proof.logIndex,
      proof.treeSize,
      proof.hashes.map((h) => Buffer.from(h, 'hex')),
    );
    expect(root.toString('hex')).not.toBe(proof.rootHash.toLowerCase());
  });

  it("verifies the REAL signed entry timestamp under the log's real public key", () => {
    /*
     * This validates our SET payload canonicalization — the field order and
     * whitespace-free JSON that Rekor signs. Getting it wrong would have made
     * every anchor look forged, and no synthetic test could have caught it
     * because the synthetic signer would share our mistake.
     */
    const ok = verify(
      'sha256',
      setPayload(entry),
      createPublicKey(logKeyPem),
      Buffer.from(entry.signedEntryTimestamp!, 'base64'),
    );
    expect(ok).toBe(true);
  });

  it('fails the real SET when any covered field is changed', () => {
    const key = createPublicKey(logKeyPem);
    const sig = Buffer.from(entry.signedEntryTimestamp!, 'base64');
    for (const mutated of [
      { ...entry, logIndex: entry.logIndex + 1 },
      { ...entry, integratedTime: entry.integratedTime + 1 },
      { ...entry, logID: entry.logID.replace(/^./, '0') },
    ]) {
      expect(verify('sha256', setPayload(mutated), key, sig)).toBe(false);
    }
  });
});
