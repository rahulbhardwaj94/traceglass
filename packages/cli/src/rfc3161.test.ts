import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  buildTimeStampRequest,
  parseTimeStampResponse,
  parseTimeStampToken,
  verifyTimeStampToken,
} from './rfc3161.js';
import { TAG, children, parseDer, readInteger } from './asn1.js';

/**
 * RFC 3161 against REAL TSA output.
 *
 * Every fixture here was produced by OpenSSL's own `ts` implementation
 * (test-fixtures/generate-tsa.sh) and independently confirmed with
 * `openssl ts -verify`. That matters: a parser tested only against its own
 * encoder tests nothing. These run fully offline — no network, no OpenSSL
 * needed at test time.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-fixtures');
const message = readFileSync(join(FIXTURES, 'message.bin'));
const requestDer = readFileSync(join(FIXTURES, 'request.tsq'));
const responseDer = readFileSync(join(FIXTURES, 'response.tsr'));
const rejectedDer = readFileSync(join(FIXTURES, 'response-rejected.tsr'));
const tsaCertPem = readFileSync(join(FIXTURES, 'tsa-cert.pem'), 'utf8');

/** The digest the fixture token covers — computed here, never hard-coded. */
const digest = createHash('sha256').update(message).digest();

/** Pull the nonce out of OpenSSL's own request so we can assert the echo. */
function nonceFromRequest(der: Buffer): Buffer {
  const kids = children(parseDer(der));
  const nonce = kids.find((c, i) => i >= 2 && c.tag === TAG.INTEGER);
  if (!nonce) throw new Error('fixture request has no nonce');
  return Buffer.from(nonce.content);
}

describe('RFC 3161 request construction', () => {
  it('builds a TimeStampReq that matches the structure OpenSSL emits', () => {
    const req = buildTimeStampRequest(digest);
    const ours = parseDer(req.der);
    const theirs = parseDer(requestDer);

    expect(ours.tag).toBe(TAG.SEQUENCE);
    expect(readInteger(children(ours)[0]!)).toBe(1); // version v1

    // messageImprint: same algorithm identifier and the same digest bytes.
    const ourImprint = children(ours)[1]!;
    const theirImprint = children(theirs)[1]!;
    expect(children(ourImprint)[0]!.raw.equals(children(theirImprint)[0]!.raw)).toBe(true);
    expect(children(ourImprint)[1]!.content.equals(digest)).toBe(true);
    expect(children(theirImprint)[1]!.content.equals(digest)).toBe(true);
  });

  it('sets certReq so the token embeds the certificate needed to verify offline', () => {
    const kids = children(parseDer(buildTimeStampRequest(digest).der));
    const bool = kids.find((c) => c.tag === TAG.BOOLEAN);
    expect(bool?.content[0]).toBe(0xff);
  });

  it('generates a fresh positive nonce per request', () => {
    const a = buildTimeStampRequest(digest).nonce;
    const b = buildTimeStampRequest(digest).nonce;
    expect(a.equals(b)).toBe(false);
    expect(a[0]! & 0x80).toBe(0); // positive, so the DER INTEGER needs no pad
  });

  it('refuses a digest whose length contradicts the named algorithm', () => {
    expect(() => buildTimeStampRequest(Buffer.alloc(20), { hashAlgorithm: 'sha256' })).toThrow(
      /32/,
    );
  });
});

describe('RFC 3161 response parsing', () => {
  it('reads a granted response and its embedded token', () => {
    const res = parseTimeStampResponse(responseDer);
    expect(res.status).toBe(0);
    expect(res.statusName).toBe('granted');
    expect(res.failInfo).toEqual([]);
    expect(res.tokenDer).not.toBeNull();
  });

  it('reads a rejection, with status text and decoded failure bits', () => {
    const res = parseTimeStampResponse(rejectedDer);
    expect(res.status).toBe(2);
    expect(res.statusName).toBe('rejection');
    expect(res.tokenDer).toBeNull();
    expect(res.failInfo).toContain('badAlg');
    expect(res.statusText[0]).toMatch(/not supported/);
  });

  it('parses the TSTInfo the TSA actually issued', () => {
    const { tstInfo } = parseTimeStampToken(parseTimeStampResponse(responseDer).tokenDer!);
    expect(tstInfo.version).toBe(1);
    expect(tstInfo.hashAlgorithm).toBe('sha256');
    expect(tstInfo.messageImprint.equals(digest)).toBe(true);
    expect(tstInfo.genTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(Number.isNaN(Date.parse(tstInfo.genTime))).toBe(false);
    expect(tstInfo.nonce).not.toBeNull();
  });
});

describe('RFC 3161 token verification', () => {
  const tokenDer = parseTimeStampResponse(responseDer).tokenDer!;

  it('verifies a genuine token: signature, content digest, imprint and nonce', () => {
    const result = verifyTimeStampToken(tokenDer, {
      expectedDigest: digest,
      expectedNonce: nonceFromRequest(requestDer),
      pinnedCertPem: tsaCertPem,
    });
    expect(result.problems).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.signatureOk).toBe(true);
    expect(result.contentDigestOk).toBe(true);
    expect(result.imprintOk).toBe(true);
    expect(result.nonceOk).toBe(true);
    expect(result.certPinned).toBe(true);
    expect(result.hasTimestampingEku).toBe(true);
    expect(result.certValidAtGenTime).toBe(true);
    expect(result.certSubject).toMatch(/traceglass test TSA/);
  });

  it('rejects a token that timestamps a DIFFERENT digest', () => {
    const other = createHash('sha256').update('some other document').digest();
    const result = verifyTimeStampToken(tokenDer, { expectedDigest: other });
    expect(result.ok).toBe(false);
    expect(result.imprintOk).toBe(false);
    expect(result.problems.join(' ')).toMatch(/messageImprint mismatch/);
  });

  it('rejects a replayed token when the nonce does not answer our request', () => {
    const result = verifyTimeStampToken(tokenDer, {
      expectedDigest: digest,
      expectedNonce: Buffer.from('0011223344556677', 'hex'),
    });
    expect(result.ok).toBe(false);
    expect(result.nonceOk).toBe(false);
    expect(result.problems.join(' ')).toMatch(/nonce mismatch/);
  });

  it('detects EVERY single-bit flip across the whole signed structure', () => {
    /*
     * Exhaustive, not sampled: for each byte of the three regions whose
     * integrity the token's security actually rests on, flip a bit and require
     * rejection. If any offset survived, some field would be silently mutable
     * after signing — genTime and the messageImprint both live in eContent, so
     * a gap here would mean a timestamp whose *time* could be edited.
     */
    const parsed = parseTimeStampToken(tokenDer);
    const attrs = parsed.signerInfo.signedAttrsDer!;
    const regions: Array<[string, number, number]> = [
      [
        'eContent (TSTInfo: genTime, imprint, serial)',
        tokenDer.indexOf(parsed.eContent),
        parsed.eContent.length,
      ],
      // signedAttrsDer is re-tagged, so locate it by its content bytes.
      ['signedAttrs', tokenDer.indexOf(attrs.subarray(4)), attrs.length - 4],
      [
        'TSA signature',
        tokenDer.indexOf(parsed.signerInfo.signature),
        parsed.signerInfo.signature.length,
      ],
    ];

    let checked = 0;
    for (const [name, start, length] of regions) {
      expect(start, `${name}: region not located in the token`).toBeGreaterThan(0);
      for (let i = start; i < start + length; i++) {
        const tampered = Buffer.from(tokenDer);
        tampered[i] = tampered[i]! ^ 0x01;
        const result = verifyTimeStampToken(tampered, { expectedDigest: digest });
        expect(result.ok, `${name}: undetected bit flip at byte ${i}`).toBe(false);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(500);
  });

  it('binds the signer certificate via the ESS signingCertificateV2 attribute', () => {
    // Without this the CMS signature alone would let an attacker swap in a
    // certificate whose private key they hold and re-sign the attributes.
    const parsed = parseTimeStampToken(tokenDer);
    expect(parsed.signerInfo.signedAttrs.has('1.2.840.113549.1.9.16.2.47')).toBe(true);
  });

  it('rejects a token whose TSTInfo content was edited after signing', () => {
    // Move genTime forward by a year, in place, keeping every length intact.
    const original = tokenDer.indexOf(Buffer.from('2026', 'ascii'));
    expect(original).toBeGreaterThan(0);
    const tampered = Buffer.from(tokenDer);
    Buffer.from('2027', 'ascii').copy(tampered, original);
    const result = verifyTimeStampToken(tampered, { expectedDigest: digest });
    expect(result.ok).toBe(false);
    // The signed messageDigest attribute no longer matches the eContent.
    expect(result.contentDigestOk).toBe(false);
  });

  it('reports certPinned=false for an unpinned token — the self-attested case', () => {
    const result = verifyTimeStampToken(tokenDer, { expectedDigest: digest });
    // Cryptographically fine, but it proves nothing about WHO timestamped it.
    expect(result.ok).toBe(true);
    expect(result.signatureOk).toBe(true);
    expect(result.certPinned).toBe(false);
    expect(result.certFingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it('fails when the token is signed by a TSA other than the pinned one', () => {
    // Any well-formed certificate that is not the signer must be rejected.
    const otherPem = readFileSync(join(FIXTURES, 'other-ca.pem'), 'utf8');
    const result = verifyTimeStampToken(tokenDer, {
      expectedDigest: digest,
      pinnedCertPem: otherPem,
    });
    expect(result.ok).toBe(false);
    expect(result.certPinned).toBe(false);
    expect(result.problems.join(' ')).toMatch(/does not match the pinned TSA certificate/);
  });

  it('treats garbage as a verification failure, never an exception', () => {
    for (const bytes of [
      Buffer.alloc(0),
      Buffer.from('not der at all'),
      Buffer.from([0x30, 0x82, 0xff, 0xff, 0x00]), // length beyond the buffer
      Buffer.from([0x30, 0x80, 0x00, 0x00]), // BER indefinite length
    ]) {
      const result = verifyTimeStampToken(bytes, { expectedDigest: digest });
      expect(result.ok).toBe(false);
      expect(result.problems.length).toBeGreaterThan(0);
    }
  });
});
