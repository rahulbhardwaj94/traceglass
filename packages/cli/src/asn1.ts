/**
 * A deliberately tiny DER (X.690 Distinguished Encoding Rules) reader/writer.
 *
 * WHY THIS EXISTS INSTEAD OF A DEPENDENCY
 * ---------------------------------------
 * RFC 3161 needs exactly two things: emit a TimeStampReq (five fields) and walk
 * a TimeStampResp to reach TSTInfo and the CMS SignerInfo. That is a few hundred
 * bytes of structure. The npm options (pkijs+asn1js, node-forge) each pull in
 * several thousand lines and a transitive tree, into a product whose entire
 * pitch is that you can audit its supply chain. See README "Dependencies".
 *
 * SCOPE AND LIMITS — read before reusing this anywhere else:
 *   - Definite-length encodings only. BER indefinite lengths (0x80) are
 *     rejected; DER forbids them, and a TSA emitting them is out of spec.
 *   - No schema layer. Callers walk the tree positionally and are responsible
 *     for checking tags. Every parse entry point is total: it throws
 *     `Asn1Error` rather than returning junk.
 *   - Not constant-time. It never touches secret material — only public
 *     certificates, timestamps and signatures — so that is acceptable here.
 */

export class Asn1Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Asn1Error';
  }
}

/* -------------------------------------------------------------------------- */
/* Tags                                                                        */
/* -------------------------------------------------------------------------- */

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
} as const;

/** Context-specific constructed tag [n], e.g. `[0]` -> 0xa0. */
export function contextTag(n: number, constructed = true): number {
  if (n < 0 || n > 30) throw new Asn1Error(`context tag ${n} out of supported range`);
  return 0x80 | (constructed ? 0x20 : 0x00) | n;
}

/* -------------------------------------------------------------------------- */
/* Reading                                                                     */
/* -------------------------------------------------------------------------- */

export interface Asn1Node {
  /** The identifier octet (single-byte tags only, which covers all of PKIX). */
  tag: number;
  /** Value bytes, excluding tag and length. */
  content: Buffer;
  /** The complete TLV exactly as it appeared — needed to re-hash structures. */
  raw: Buffer;
}

/** True for tags whose value is itself a sequence of TLVs. */
export function isConstructed(tag: number): boolean {
  return (tag & 0x20) !== 0;
}

/**
 * Read one TLV starting at `offset`.
 * Returns the node plus the offset just past it.
 */
export function readTlv(buf: Buffer, offset = 0): { node: Asn1Node; end: number } {
  if (offset + 2 > buf.length) throw new Asn1Error('truncated: no room for tag and length');
  const tag = buf[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new Asn1Error('multi-byte tags are not supported');

  const first = buf[offset + 1]!;
  let length: number;
  let headerLen: number;

  if (first < 0x80) {
    length = first;
    headerLen = 2;
  } else if (first === 0x80) {
    throw new Asn1Error('indefinite-length encoding is not valid DER');
  } else {
    const numBytes = first & 0x7f;
    // 4 bytes of length is 4 GiB; anything beyond is malicious or corrupt.
    if (numBytes > 4) throw new Asn1Error(`length field too large (${numBytes} bytes)`);
    if (offset + 2 + numBytes > buf.length) throw new Asn1Error('truncated: length field');
    length = 0;
    for (let i = 0; i < numBytes; i++) length = length * 256 + buf[offset + 2 + i]!;
    headerLen = 2 + numBytes;
  }

  const start = offset + headerLen;
  const end = start + length;
  if (end > buf.length) {
    throw new Asn1Error(`truncated: declared length ${length} exceeds available bytes`);
  }
  return {
    node: {
      tag,
      content: buf.subarray(start, end),
      raw: buf.subarray(offset, end),
    },
    end,
  };
}

/** Parse a single top-level TLV and require it to consume the whole buffer. */
export function parseDer(buf: Buffer): Asn1Node {
  const { node, end } = readTlv(buf, 0);
  if (end !== buf.length) {
    throw new Asn1Error(`trailing data after top-level structure (${buf.length - end} bytes)`);
  }
  return node;
}

/** Split a constructed node's content into its child TLVs. */
export function children(node: Asn1Node): Asn1Node[] {
  if (!isConstructed(node.tag)) {
    throw new Asn1Error(`cannot read children of primitive tag 0x${node.tag.toString(16)}`);
  }
  const out: Asn1Node[] = [];
  let offset = 0;
  while (offset < node.content.length) {
    const { node: child, end } = readTlv(node.content, offset);
    out.push(child);
    offset = end;
  }
  return out;
}

/** Child at `index`, asserting its tag when `expectTag` is given. */
export function childAt(node: Asn1Node, index: number, expectTag?: number): Asn1Node {
  const kids = children(node);
  const child = kids[index];
  if (!child) throw new Asn1Error(`missing child #${index} (have ${kids.length})`);
  if (expectTag !== undefined && child.tag !== expectTag) {
    throw new Asn1Error(
      `child #${index}: expected tag 0x${expectTag.toString(16)}, got 0x${child.tag.toString(16)}`,
    );
  }
  return child;
}

/** First child carrying `tag`, or undefined. Used for OPTIONAL fields. */
export function findChild(node: Asn1Node, tag: number): Asn1Node | undefined {
  return children(node).find((c) => c.tag === tag);
}

/** Decode an INTEGER as a JS number; throws if it will not fit exactly. */
export function readInteger(node: Asn1Node): number {
  if (node.tag !== TAG.INTEGER) throw new Asn1Error('not an INTEGER');
  if (node.content.length === 0) throw new Asn1Error('empty INTEGER');
  if (node.content.length > 6) throw new Asn1Error('INTEGER too large for a JS number');
  let value = 0;
  const negative = (node.content[0]! & 0x80) !== 0;
  for (const byte of node.content) value = value * 256 + byte;
  if (negative) value -= Math.pow(256, node.content.length);
  return value;
}

/** Decode an OBJECT IDENTIFIER to dotted-decimal form. */
export function readOid(node: Asn1Node): string {
  if (node.tag !== TAG.OID) throw new Asn1Error('not an OBJECT IDENTIFIER');
  const bytes = node.content;
  if (bytes.length === 0) throw new Asn1Error('empty OID');

  // Every arc is base-128 with a continuation bit; the FIRST decoded value
  // packs two arcs as 40*arc1 + arc2 (X.690 §8.19.4). That combined value is
  // not limited to one byte: under the 2.x arc, arc2 may exceed 39 and push it
  // into multi-byte territory, so it has to be decoded as a full base-128
  // value before being split.
  const values: number[] = [];
  let value = 0;
  for (const byte of bytes) {
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      values.push(value);
      value = 0;
    }
  }
  if (value !== 0) throw new Asn1Error('OID ends mid-value');

  const first = values.shift()!;
  const arc1 = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [arc1, first - arc1 * 40, ...values].join('.');
}

/**
 * Decode a GeneralizedTime to an ISO 8601 string.
 *
 * DER pins the format to `YYYYMMDDHHMMSS[.fff]Z` — always UTC, no offsets — so
 * anything else is rejected rather than guessed at. Getting this wrong would
 * misreport *when* a record was proven to exist, which is the whole claim.
 */
export function readGeneralizedTime(node: Asn1Node): string {
  if (node.tag !== TAG.GENERALIZED_TIME) throw new Asn1Error('not a GeneralizedTime');
  const text = node.content.toString('ascii');
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?Z$/.exec(text);
  if (!match) throw new Asn1Error(`unsupported GeneralizedTime format: "${text}"`);
  const [, y, mo, d, h, mi, s, frac] = match;
  const ms = frac ? frac.padEnd(3, '0').slice(0, 3) : '000';
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}.${ms}Z`;
  if (Number.isNaN(Date.parse(iso))) throw new Asn1Error(`invalid GeneralizedTime: "${text}"`);
  return iso;
}

/* -------------------------------------------------------------------------- */
/* Writing                                                                     */
/* -------------------------------------------------------------------------- */

/** DER length octets for a value of `length` bytes. */
function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Wrap raw content bytes in a tag + DER length. */
export function encodeTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export function encodeSequence(...items: Buffer[]): Buffer {
  return encodeTlv(TAG.SEQUENCE, Buffer.concat(items));
}

export function encodeOctetString(content: Buffer): Buffer {
  return encodeTlv(TAG.OCTET_STRING, content);
}

export function encodeBoolean(value: boolean): Buffer {
  return encodeTlv(TAG.BOOLEAN, Buffer.from([value ? 0xff : 0x00]));
}

export function encodeNull(): Buffer {
  return encodeTlv(TAG.NULL, Buffer.alloc(0));
}

/**
 * Encode a non-negative integer. DER integers are two's complement, so a
 * leading byte >= 0x80 needs a 0x00 pad or it reads back as negative.
 */
export function encodeInteger(value: number | Buffer): Buffer {
  let bytes: Buffer;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) {
      throw new Asn1Error('only non-negative integers are supported');
    }
    if (value === 0) return encodeTlv(TAG.INTEGER, Buffer.from([0]));
    const acc: number[] = [];
    let remaining = value;
    while (remaining > 0) {
      acc.unshift(remaining % 256);
      remaining = Math.floor(remaining / 256);
    }
    bytes = Buffer.from(acc);
  } else {
    // Strip leading zeros so the encoding is canonical, then re-pad if needed.
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    bytes = value.subarray(start);
    if (bytes.length === 0) bytes = Buffer.from([0]);
  }
  if (bytes[0]! & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return encodeTlv(TAG.INTEGER, bytes);
}

/** Base-128, big-endian, continuation bit set on all but the last octet. */
function encodeBase128(value: number): number[] {
  const chunk: number[] = [value % 128];
  let remaining = Math.floor(value / 128);
  while (remaining > 0) {
    chunk.unshift((remaining % 128) | 0x80);
    remaining = Math.floor(remaining / 128);
  }
  return chunk;
}

/** Encode dotted-decimal OID text. */
export function encodeOid(dotted: string): Buffer {
  const parts = dotted.split('.').map((p) => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0) throw new Asn1Error(`invalid OID arc "${p}"`);
    return n;
  });
  if (parts.length < 2) throw new Asn1Error('an OID needs at least two arcs');
  if (parts[0]! > 2) throw new Asn1Error(`invalid OID root arc ${parts[0]}`);
  if (parts[0]! < 2 && parts[1]! > 39) {
    throw new Asn1Error(`OID arc 2 must be < 40 under root ${parts[0]}`);
  }
  // The first two arcs share one base-128 value; the combined number can need
  // several octets, so it must go through the same encoder as every other arc.
  const bytes: number[] = encodeBase128(parts[0]! * 40 + parts[1]!);
  for (const arc of parts.slice(2)) bytes.push(...encodeBase128(arc));
  return encodeTlv(TAG.OID, Buffer.from(bytes));
}

/** AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }. */
export function encodeAlgorithmIdentifier(oid: string, withNullParams = true): Buffer {
  return encodeSequence(encodeOid(oid), ...(withNullParams ? [encodeNull()] : []));
}
