import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  Asn1Error,
  TAG,
  children,
  contextTag,
  encodeInteger,
  encodeOid,
  encodeSequence,
  encodeTlv,
  parseDer,
  readGeneralizedTime,
  readInteger,
  readOid,
  readTlv,
} from './asn1.js';

/**
 * The DER layer is hand-rolled (see the rationale at the top of asn1.ts), so it
 * carries the burden of proving itself. Two kinds of test here:
 *
 *   1. KNOWN-ANSWER vectors — byte sequences fixed by X.690 and by the PKIX
 *      OID registry, which cannot be satisfied by a self-consistent-but-wrong
 *      implementation.
 *   2. HOSTILE INPUT — this parser runs over bytes an attacker supplies via an
 *      anchors file. It must never hang, over-read, or throw something other
 *      than Asn1Error.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-fixtures');

describe('DER length encoding', () => {
  it('uses the short form below 128 bytes and the long form at or above it', () => {
    // X.690 §8.1.3: lengths 0..127 are a single octet; 128+ use 0x80|n then n
    // big-endian octets. Getting this boundary wrong corrupts every structure
    // larger than a couple of hashes.
    expect([...encodeTlv(0x04, Buffer.alloc(0)).subarray(0, 2)]).toEqual([0x04, 0x00]);
    expect([...encodeTlv(0x04, Buffer.alloc(127)).subarray(0, 2)]).toEqual([0x04, 0x7f]);
    expect([...encodeTlv(0x04, Buffer.alloc(128)).subarray(0, 3)]).toEqual([0x04, 0x81, 0x80]);
    expect([...encodeTlv(0x04, Buffer.alloc(255)).subarray(0, 3)]).toEqual([0x04, 0x81, 0xff]);
    expect([...encodeTlv(0x04, Buffer.alloc(256)).subarray(0, 4)]).toEqual([
      0x04, 0x82, 0x01, 0x00,
    ]);
    expect([...encodeTlv(0x04, Buffer.alloc(65536)).subarray(0, 5)]).toEqual([
      0x04, 0x83, 0x01, 0x00, 0x00,
    ]);
  });

  it('round-trips every length across the short/long boundary', () => {
    for (const size of [0, 1, 126, 127, 128, 129, 255, 256, 257, 4096]) {
      const content = Buffer.alloc(size, 0xab);
      const { node, end } = readTlv(encodeTlv(TAG.OCTET_STRING, content));
      expect(node.content.length).toBe(size);
      expect(node.content.equals(content)).toBe(true);
      expect(end).toBe(encodeTlv(TAG.OCTET_STRING, content).length);
    }
  });
});

describe('DER INTEGER', () => {
  it('pads values whose high bit is set, so they do not read back negative', () => {
    // X.690 §8.3.2 — two's complement. 0x80 must encode as 00 80.
    expect([...encodeInteger(0)]).toEqual([0x02, 0x01, 0x00]);
    expect([...encodeInteger(1)]).toEqual([0x02, 0x01, 0x01]);
    expect([...encodeInteger(127)]).toEqual([0x02, 0x01, 0x7f]);
    expect([...encodeInteger(128)]).toEqual([0x02, 0x02, 0x00, 0x80]);
    expect([...encodeInteger(255)]).toEqual([0x02, 0x02, 0x00, 0xff]);
    expect([...encodeInteger(256)]).toEqual([0x02, 0x02, 0x01, 0x00]);
  });

  it('pads a Buffer nonce the same way and strips redundant leading zeros', () => {
    expect([...encodeInteger(Buffer.from([0x80, 0x01]))]).toEqual([0x02, 0x03, 0x00, 0x80, 0x01]);
    expect([...encodeInteger(Buffer.from([0x00, 0x00, 0x42]))]).toEqual([0x02, 0x01, 0x42]);
    expect([...encodeInteger(Buffer.from([0x00]))]).toEqual([0x02, 0x01, 0x00]);
  });

  it('reads signed values back correctly', () => {
    for (const value of [0, 1, 127, 128, 255, 256, 65535, 1 << 20]) {
      expect(readInteger(parseDer(encodeInteger(value)))).toBe(value);
    }
    // A genuinely negative INTEGER (0xFF = -1) must not read as 255.
    expect(readInteger(parseDer(Buffer.from([0x02, 0x01, 0xff])))).toBe(-1);
  });

  it('refuses negative and non-integer inputs rather than encoding nonsense', () => {
    expect(() => encodeInteger(-1)).toThrow(Asn1Error);
    expect(() => encodeInteger(1.5)).toThrow(Asn1Error);
  });
});

describe('DER OBJECT IDENTIFIER', () => {
  it('matches the registered encodings of well-known OIDs', () => {
    // These byte strings are fixed by the PKIX registry — an implementation
    // that merely round-trips its own output cannot produce them by accident.
    expect(encodeOid('1.2.840.113549.1.1.11').toString('hex')).toBe(
      '06092a864886f70d01010b', // sha256WithRSAEncryption
    );
    expect(encodeOid('2.16.840.1.101.3.4.2.1').toString('hex')).toBe(
      '0609608648016503040201', // id-sha256
    );
    expect(encodeOid('1.3.6.1.5.5.7.3.8').toString('hex')).toBe(
      '06082b06010505070308', // id-kp-timeStamping
    );
    expect(encodeOid('1.3.101.112').toString('hex')).toBe('06032b6570'); // Ed25519
  });

  it('round-trips OIDs with multi-byte arcs', () => {
    for (const oid of [
      '1.2.840.113549.1.9.16.2.47',
      '2.5.29.37',
      '1.3.6.1.4.1.99999.1.1',
      '0.0',
      '2.999.1',
    ]) {
      expect(readOid(parseDer(encodeOid(oid)))).toBe(oid);
    }
  });

  it('rejects malformed OIDs in both directions', () => {
    expect(() => encodeOid('1')).toThrow(/at least two arcs/);
    expect(() => encodeOid('1.x.3')).toThrow(/invalid OID arc/);
    // An OID whose final byte still has the continuation bit set is truncated.
    expect(() => readOid(parseDer(Buffer.from([0x06, 0x02, 0x2a, 0x86])))).toThrow(/mid-value/);
    expect(() => readOid(parseDer(Buffer.from([0x06, 0x00])))).toThrow(/empty OID/);
  });
});

describe('GeneralizedTime', () => {
  it('parses the DER-restricted UTC form, with and without fractional seconds', () => {
    const parse = (text: string) =>
      readGeneralizedTime(parseDer(encodeTlv(TAG.GENERALIZED_TIME, Buffer.from(text, 'ascii'))));
    expect(parse('20260725125735Z')).toBe('2026-07-25T12:57:35.000Z');
    expect(parse('20260725125735.5Z')).toBe('2026-07-25T12:57:35.500Z');
    expect(parse('20260725125735.123Z')).toBe('2026-07-25T12:57:35.123Z');
  });

  it('rejects the non-DER forms rather than guessing at a time', () => {
    /*
     * Guessing here would misreport WHEN a record was proven to exist, which is
     * the entire claim an RFC 3161 anchor makes. Local time and offsets are
     * forbidden by DER; anything unparseable must fail loudly.
     */
    const parse = (text: string) =>
      readGeneralizedTime(parseDer(encodeTlv(TAG.GENERALIZED_TIME, Buffer.from(text, 'ascii'))));
    for (const bad of [
      '20260725125735', // no Z — local time
      '20260725125735+0100', // offset
      '202607251257Z', // minutes precision
      '20261325125735Z', // month 13
      '', // empty
      'not a time at all',
    ]) {
      expect(() => parse(bad), bad).toThrow(Asn1Error);
    }
  });
});

describe('hostile input', () => {
  it('never over-reads, and always fails with Asn1Error', () => {
    const cases: Array<[string, Buffer]> = [
      ['empty', Buffer.alloc(0)],
      ['tag only', Buffer.from([0x30])],
      ['length beyond buffer', Buffer.from([0x30, 0x82, 0xff, 0xff, 0x00])],
      ['BER indefinite length', Buffer.from([0x30, 0x80, 0x00, 0x00])],
      ['long-form length header truncated', Buffer.from([0x30, 0x84, 0x00])],
      ['absurd 5-byte length', Buffer.from([0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05])],
      ['multi-byte tag', Buffer.from([0x1f, 0x01, 0x00])],
      ['trailing garbage', Buffer.concat([encodeInteger(1), Buffer.from([0x00])])],
    ];
    for (const [name, bytes] of cases) {
      expect(() => parseDer(bytes), name).toThrow(Asn1Error);
    }
  });

  it('reports a truncated child inside a well-formed parent', () => {
    // Parent claims 4 bytes; the child inside claims 10.
    const bytes = Buffer.from([0x30, 0x04, 0x04, 0x0a, 0x01, 0x02]);
    expect(() => children(parseDer(bytes))).toThrow(Asn1Error);
  });

  it('refuses to walk into a primitive as if it were constructed', () => {
    expect(() => children(parseDer(encodeInteger(5)))).toThrow(/primitive/);
  });

  it('rejects INTEGERs too large to represent exactly as a JS number', () => {
    // Silently losing precision on a serial number would be worse than failing.
    expect(() => readInteger(parseDer(Buffer.from([0x02, 0x08, 1, 2, 3, 4, 5, 6, 7, 8])))).toThrow(
      /too large/,
    );
  });
});

describe('against real-world DER', () => {
  it('walks the OpenSSL-issued TSA certificate structure', () => {
    const pem = readFileSync(join(FIXTURES, 'tsa-cert.pem'), 'utf8');
    const der = Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
    const cert = parseDer(der);
    expect(cert.tag).toBe(TAG.SEQUENCE);

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    const parts = children(cert);
    expect(parts).toHaveLength(3);
    expect(parts[2]!.tag).toBe(TAG.BIT_STRING);

    // tbsCertificate starts with [0] EXPLICIT version for a v3 certificate.
    const tbs = children(parts[0]!);
    expect(tbs[0]!.tag).toBe(contextTag(0));
    expect(readInteger(children(tbs[0]!)[0]!)).toBe(2); // v3

    // The signature algorithm is the one OpenSSL was told to use.
    expect(readOid(children(parts[1]!)[0]!)).toBe('1.2.840.113549.1.1.11');
  });

  it('re-encodes a parsed SEQUENCE to the identical bytes', () => {
    const request = readFileSync(join(FIXTURES, 'request.tsq'));
    const parsed = parseDer(request);
    const reencoded = encodeSequence(...children(parsed).map((c) => Buffer.from(c.raw)));
    expect(reencoded.equals(request)).toBe(true);
  });
});
