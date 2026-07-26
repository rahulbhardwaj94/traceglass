import { X509Certificate, constants, createHash, randomBytes, verify } from 'node:crypto';
import {
  Asn1Error,
  TAG,
  type Asn1Node,
  childAt,
  children,
  contextTag,
  encodeAlgorithmIdentifier,
  encodeBoolean,
  encodeInteger,
  encodeOctetString,
  encodeOid,
  encodeSequence,
  encodeTlv,
  findChild,
  parseDer,
  readGeneralizedTime,
  readInteger,
  readOid,
} from './asn1.js';

/**
 * RFC 3161 Time-Stamp Protocol: request construction, response parsing, and
 * — the part that actually matters — token verification.
 *
 * A stored timestamp token that is never validated is theatre. It looks like
 * evidence in the file and proves nothing, because nobody ever checked that the
 * bytes are a real signature over *our* digest. So `verifyTimeStampToken` is the
 * centre of this module and runs at anchor time as well as at verify time: we
 * refuse to record a token we could not validate.
 *
 * WHAT A VERIFIED TOKEN PROVES — and the one thing it does not
 * ------------------------------------------------------------
 * A token that passes here establishes:
 *   1. the TSA's signature over the TSTInfo is cryptographically valid;
 *   2. the TSTInfo's messageImprint equals the digest we submitted, so the
 *      timestamp is over OUR statement and not some other document;
 *   3. the nonce we generated is echoed back, so the response is not a replay
 *      of an older token;
 *   4. `genTime` — the instant the TSA asserts the digest was presented to it.
 *
 * It does NOT establish that the signing certificate belongs to a TSA you have
 * any reason to trust. Verifying a token against the certificate embedded in
 * that same token is the identical closed loop as verifying a run's signature
 * against the public key embedded in the run (docs/threat-model.md §4.1): an
 * attacker mints their own "TSA", signs whatever genTime they like, and it
 * verifies cleanly. Path-building to a trusted root is deliberately NOT
 * implemented here — Node exposes no chain verifier, and a half-built one is
 * worse than an honest gap. Instead the caller may PIN the expected TSA
 * certificate (`--tsa-cert`), which is what converts a self-attested token into
 * a third-party attestation. Verification results carry `certPinned` so callers
 * can never accidentally report the weak case as the strong one.
 */

/* -------------------------------------------------------------------------- */
/* OIDs                                                                        */
/* -------------------------------------------------------------------------- */

const OID = {
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  sha1: '1.3.14.3.2.26',
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  attrContentType: '1.2.840.113549.1.9.3',
  attrMessageDigest: '1.2.840.113549.1.9.4',
  attrSigningCertificate: '1.2.840.113549.1.9.16.2.12',
  attrSigningCertificateV2: '1.2.840.113549.1.9.16.2.47',
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaPss: '1.2.840.113549.1.1.10',
  sha256WithRsa: '1.2.840.113549.1.1.11',
  sha384WithRsa: '1.2.840.113549.1.1.12',
  sha512WithRsa: '1.2.840.113549.1.1.13',
  sha1WithRsa: '1.2.840.113549.1.1.5',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
  ecdsaWithSha384: '1.2.840.10045.4.3.3',
  ecdsaWithSha512: '1.2.840.10045.4.3.4',
  ed25519: '1.3.101.112',
} as const;

const DIGEST_BY_OID = new Map<string, HashName>([
  [OID.sha256, 'sha256'],
  [OID.sha384, 'sha384'],
  [OID.sha512, 'sha512'],
  [OID.sha1, 'sha1'],
]);

const OID_BY_DIGEST = new Map<HashName, string>([
  ['sha256', OID.sha256],
  ['sha384', OID.sha384],
  ['sha512', OID.sha512],
]);

export type HashName = 'sha256' | 'sha384' | 'sha512' | 'sha1';

/** Digest algorithms we will submit. SHA-1 is readable but never requested. */
export type RequestHashName = 'sha256' | 'sha384' | 'sha512';

/* -------------------------------------------------------------------------- */
/* Request                                                                     */
/* -------------------------------------------------------------------------- */

export interface TimeStampRequest {
  /** DER bytes to POST as `application/timestamp-query`. */
  der: Buffer;
  /** The nonce we generated; the response must echo it back exactly. */
  nonce: Buffer;
  hashAlgorithm: RequestHashName;
  digest: Buffer;
}

/**
 * Build a TimeStampReq over an already-computed digest.
 *
 *   TimeStampReq ::= SEQUENCE {
 *     version        INTEGER { v1(1) },
 *     messageImprint MessageImprint,
 *     reqPolicy      TSAPolicyId OPTIONAL,
 *     nonce          INTEGER OPTIONAL,
 *     certReq        BOOLEAN DEFAULT FALSE,
 *     extensions     [0] IMPLICIT Extensions OPTIONAL }
 *
 * `certReq` defaults to TRUE here: without the signing certificate in the
 * response we could not verify the token offline later, which is the point.
 */
export function buildTimeStampRequest(
  digest: Buffer,
  opts: {
    hashAlgorithm?: RequestHashName;
    nonce?: Buffer;
    reqPolicy?: string;
    certReq?: boolean;
  } = {},
): TimeStampRequest {
  const hashAlgorithm = opts.hashAlgorithm ?? 'sha256';
  const expectedLength = { sha256: 32, sha384: 48, sha512: 64 }[hashAlgorithm];
  if (digest.length !== expectedLength) {
    throw new Asn1Error(
      `digest is ${digest.length} bytes but ${hashAlgorithm} produces ${expectedLength}`,
    );
  }
  // 64-bit nonce: large enough that a TSA cannot plausibly replay a prior token.
  const nonce = opts.nonce ?? randomNonce();
  const algOid = OID_BY_DIGEST.get(hashAlgorithm)!;

  const messageImprint = encodeSequence(
    encodeAlgorithmIdentifier(algOid),
    encodeOctetString(digest),
  );

  const der = encodeSequence(
    encodeInteger(1),
    messageImprint,
    ...(opts.reqPolicy ? [encodeOid(opts.reqPolicy)] : []),
    encodeInteger(nonce),
    encodeBoolean(opts.certReq ?? true),
  );

  return { der, nonce, hashAlgorithm, digest };
}

function randomNonce(): Buffer {
  // Top bit cleared: DER INTEGERs are signed, and a positive nonce avoids the
  // padding byte that some TSAs mishandle when echoing it back.
  const buf = randomBytes(8);
  buf[0] = buf[0]! & 0x7f;
  if (buf[0] === 0) buf[0] = 0x01;
  return buf;
}

/* -------------------------------------------------------------------------- */
/* Response                                                                    */
/* -------------------------------------------------------------------------- */

/** PKIStatus values (RFC 3161 §2.4.2). 0 and 1 carry a token; the rest do not. */
export const PKI_STATUS: Record<number, string> = {
  0: 'granted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification',
};

/** PKIFailureInfo bit positions (RFC 3161 §2.4.2). */
const FAIL_INFO_BITS: Record<number, string> = {
  0: 'badAlg',
  2: 'badRequest',
  5: 'badDataFormat',
  14: 'timeNotAvailable',
  15: 'unacceptedPolicy',
  16: 'unacceptedExtension',
  17: 'addInfoNotAvailable',
  25: 'systemFailure',
};

export interface TimeStampResponse {
  status: number;
  statusName: string;
  statusText: string[];
  failInfo: string[];
  /** DER of the ContentInfo, or null when the TSA refused. */
  tokenDer: Buffer | null;
}

/**
 *   TimeStampResp ::= SEQUENCE {
 *     status         PKIStatusInfo,
 *     timeStampToken TimeStampToken OPTIONAL }
 */
export function parseTimeStampResponse(der: Buffer): TimeStampResponse {
  const root = parseDer(der);
  if (root.tag !== TAG.SEQUENCE) throw new Asn1Error('TimeStampResp: expected a SEQUENCE');
  const kids = children(root);

  const statusInfo = kids[0];
  if (!statusInfo || statusInfo.tag !== TAG.SEQUENCE) {
    throw new Asn1Error('TimeStampResp: missing PKIStatusInfo');
  }
  const statusKids = children(statusInfo);
  const status = readInteger(childAt(statusInfo, 0, TAG.INTEGER));

  const statusText: string[] = [];
  const freeText = statusKids.find((c, i) => i > 0 && c.tag === TAG.SEQUENCE);
  if (freeText) {
    for (const item of children(freeText)) statusText.push(item.content.toString('utf8'));
  }

  const failInfo: string[] = [];
  const failNode = statusKids.find((c) => c.tag === TAG.BIT_STRING);
  if (failNode && failNode.content.length > 1) {
    const unused = failNode.content[0]!;
    const bits = failNode.content.subarray(1);
    const totalBits = bits.length * 8 - unused;
    for (let bit = 0; bit < totalBits; bit++) {
      const byte = bits[Math.floor(bit / 8)]!;
      if (byte & (0x80 >> (bit % 8))) failInfo.push(FAIL_INFO_BITS[bit] ?? `bit${bit}`);
    }
  }

  const token = kids[1];
  return {
    status,
    statusName: PKI_STATUS[status] ?? `unknown(${status})`,
    statusText,
    failInfo,
    tokenDer: token ? Buffer.from(token.raw) : null,
  };
}

/* -------------------------------------------------------------------------- */
/* Token parsing                                                               */
/* -------------------------------------------------------------------------- */

export interface TstInfo {
  version: number;
  policy: string;
  hashAlgorithm: HashName;
  /** The digest the TSA countersigned. */
  messageImprint: Buffer;
  /** Hex, as issued by the TSA. */
  serialNumber: string;
  /** ISO 8601 UTC — the instant the TSA asserts. */
  genTime: string;
  nonce: Buffer | null;
}

export interface ParsedToken {
  tstInfo: TstInfo;
  /** DER of the eContent (the TSTInfo), needed for the messageDigest attr. */
  eContent: Buffer;
  certificates: X509Certificate[];
  signerInfo: SignerInfo;
}

interface SignerInfo {
  digestAlgorithm: HashName;
  signatureAlgorithmOid: string;
  signatureAlgorithmParams: Asn1Node | undefined;
  signature: Buffer;
  /** Re-encoded as an explicit SET — the exact bytes the TSA signed. */
  signedAttrsDer: Buffer | null;
  signedAttrs: Map<string, Asn1Node[]>;
  /** IssuerAndSerialNumber, when the signer is identified that way. */
  sid: { issuerDer: Buffer; serialDer: Buffer } | null;
}

/**
 *   TimeStampToken ::= ContentInfo {
 *     contentType id-signedData,
 *     content [0] EXPLICIT SignedData }
 */
export function parseTimeStampToken(tokenDer: Buffer): ParsedToken {
  const contentInfo = parseDer(tokenDer);
  if (contentInfo.tag !== TAG.SEQUENCE) throw new Asn1Error('token: expected ContentInfo SEQUENCE');
  const contentType = readOid(childAt(contentInfo, 0, TAG.OID));
  if (contentType !== OID.signedData) {
    throw new Asn1Error(`token: expected SignedData content, got OID ${contentType}`);
  }
  const explicit = childAt(contentInfo, 1, contextTag(0));
  const signedData = childAt(explicit, 0, TAG.SEQUENCE);
  const sdKids = children(signedData);

  // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
  //                           certificates [0] IMPLICIT OPTIONAL,
  //                           crls [1] IMPLICIT OPTIONAL, signerInfos SET }
  const encap = sdKids[2];
  if (!encap || encap.tag !== TAG.SEQUENCE) throw new Asn1Error('token: missing encapContentInfo');
  const encapType = readOid(childAt(encap, 0, TAG.OID));
  if (encapType !== OID.tstInfo) {
    throw new Asn1Error(`token: encapsulated content is not TSTInfo (OID ${encapType})`);
  }
  const eContentExplicit = childAt(encap, 1, contextTag(0));
  const eContentOctets = childAt(eContentExplicit, 0, TAG.OCTET_STRING);
  const eContent = Buffer.from(eContentOctets.content);

  const certificates: X509Certificate[] = [];
  const certsNode = sdKids.find((c) => c.tag === contextTag(0));
  if (certsNode) {
    for (const certNode of children(certsNode)) {
      // Skip non-X.509 CertificateChoices (attribute certs etc.).
      if (certNode.tag !== TAG.SEQUENCE) continue;
      try {
        certificates.push(new X509Certificate(Buffer.from(certNode.raw)));
      } catch {
        // A certificate we cannot parse simply is not a verification candidate.
      }
    }
  }

  const signerInfosNode = sdKids.find((c, i) => i >= 3 && c.tag === TAG.SET);
  if (!signerInfosNode) throw new Asn1Error('token: missing signerInfos');
  const signerInfoNode = children(signerInfosNode)[0];
  if (!signerInfoNode) throw new Asn1Error('token: signerInfos is empty');

  return {
    tstInfo: parseTstInfo(eContent),
    eContent,
    certificates,
    signerInfo: parseSignerInfo(signerInfoNode),
  };
}

function parseSignerInfo(node: Asn1Node): SignerInfo {
  const kids = children(node);
  // [ version, sid, digestAlgorithm, [0] signedAttrs?, sigAlgorithm, signature, [1] unsigned? ]
  const sidNode = kids[1];
  let sid: SignerInfo['sid'] = null;
  if (sidNode && sidNode.tag === TAG.SEQUENCE) {
    const sidKids = children(sidNode);
    if (sidKids[0] && sidKids[1]) {
      sid = { issuerDer: Buffer.from(sidKids[0].raw), serialDer: Buffer.from(sidKids[1].raw) };
    }
  }

  const digestAlgNode = kids[2];
  if (!digestAlgNode) throw new Asn1Error('signerInfo: missing digestAlgorithm');
  const digestOid = readOid(childAt(digestAlgNode, 0, TAG.OID));
  const digestAlgorithm = DIGEST_BY_OID.get(digestOid);
  if (!digestAlgorithm) throw new Asn1Error(`signerInfo: unsupported digest OID ${digestOid}`);

  const signedAttrsNode = kids.find((c) => c.tag === contextTag(0));
  let signedAttrsDer: Buffer | null = null;
  const signedAttrs = new Map<string, Asn1Node[]>();
  if (signedAttrsNode) {
    // CMS signs the attributes re-tagged as an explicit SET OF (RFC 5652 §5.4),
    // not with the [0] IMPLICIT tag they carry on the wire. Re-encoding the
    // content under 0x31 reproduces exactly the bytes the signer hashed.
    signedAttrsDer = encodeTlv(TAG.SET, Buffer.from(signedAttrsNode.content));
    for (const attr of children(signedAttrsNode)) {
      const oid = readOid(childAt(attr, 0, TAG.OID));
      const values = childAt(attr, 1, TAG.SET);
      signedAttrs.set(oid, children(values));
    }
  }

  const sigAlgIndex = kids.findIndex(
    (c, i) => i > 2 && c.tag === TAG.SEQUENCE && c !== signedAttrsNode,
  );
  const sigAlgNode = kids[sigAlgIndex];
  if (!sigAlgNode) throw new Asn1Error('signerInfo: missing signatureAlgorithm');
  const signatureAlgorithmOid = readOid(childAt(sigAlgNode, 0, TAG.OID));
  const signatureAlgorithmParams = children(sigAlgNode)[1];

  const signatureNode = kids[sigAlgIndex + 1];
  if (!signatureNode || signatureNode.tag !== TAG.OCTET_STRING) {
    throw new Asn1Error('signerInfo: missing signature');
  }

  return {
    digestAlgorithm,
    signatureAlgorithmOid,
    signatureAlgorithmParams,
    signature: Buffer.from(signatureNode.content),
    signedAttrsDer,
    signedAttrs,
    sid,
  };
}

/**
 *   TSTInfo ::= SEQUENCE {
 *     version INTEGER, policy TSAPolicyId, messageImprint MessageImprint,
 *     serialNumber INTEGER, genTime GeneralizedTime, accuracy OPTIONAL,
 *     ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL,
 *     tsa [0] OPTIONAL, extensions [1] IMPLICIT OPTIONAL }
 */
export function parseTstInfo(der: Buffer): TstInfo {
  const root = parseDer(der);
  if (root.tag !== TAG.SEQUENCE) throw new Asn1Error('TSTInfo: expected a SEQUENCE');
  const kids = children(root);

  const version = readInteger(childAt(root, 0, TAG.INTEGER));
  const policy = readOid(childAt(root, 1, TAG.OID));

  const imprint = childAt(root, 2, TAG.SEQUENCE);
  const imprintAlgOid = readOid(childAt(childAt(imprint, 0, TAG.SEQUENCE), 0, TAG.OID));
  const hashAlgorithm = DIGEST_BY_OID.get(imprintAlgOid);
  if (!hashAlgorithm) {
    throw new Asn1Error(`TSTInfo: unsupported messageImprint algorithm OID ${imprintAlgOid}`);
  }
  const messageImprint = Buffer.from(childAt(imprint, 1, TAG.OCTET_STRING).content);

  const serialNumber = childAt(root, 3, TAG.INTEGER).content.toString('hex');
  const genTime = readGeneralizedTime(childAt(root, 4, TAG.GENERALIZED_TIME));

  // The nonce is the only INTEGER after genTime; accuracy is a SEQUENCE and
  // ordering a BOOLEAN, so a positional scan past index 4 is unambiguous.
  let nonce: Buffer | null = null;
  for (let i = 5; i < kids.length; i++) {
    const kid = kids[i]!;
    if (kid.tag === TAG.INTEGER) {
      nonce = Buffer.from(kid.content);
      break;
    }
  }

  return { version, policy, hashAlgorithm, messageImprint, serialNumber, genTime, nonce };
}

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

export interface TokenVerification {
  /** True only when every check below that we can perform passed. */
  ok: boolean;
  /** The TSA's asserted time — meaningless unless `ok`. */
  genTime: string;
  /** messageImprint equals the digest we expected. */
  imprintOk: boolean;
  /** The CMS signature over signedAttrs is valid under the signer certificate. */
  signatureOk: boolean;
  /** signedAttrs' messageDigest matches SHA-x(eContent). */
  contentDigestOk: boolean;
  /** The nonce we sent was echoed back (null when we did not check one). */
  nonceOk: boolean | null;
  /** The signer certificate matched an out-of-band pin. FALSE MEANS SELF-ATTESTED. */
  certPinned: boolean;
  /** SHA-256 fingerprint of the signer certificate, for pinning. */
  certFingerprint: string | null;
  certSubject: string | null;
  /** genTime falls inside the signer certificate's validity window. */
  certValidAtGenTime: boolean | null;
  /** The signer cert carries the critical timeStamping EKU. */
  hasTimestampingEku: boolean | null;
  tstInfo: TstInfo | null;
  /** Human-readable reasons for any failure. Empty when ok. */
  problems: string[];
}

export interface VerifyTokenOptions {
  /** Reject unless the messageImprint equals this digest. */
  expectedDigest: Buffer;
  /** Reject unless the token echoes this nonce. */
  expectedNonce?: Buffer | undefined;
  /**
   * PEM of the TSA certificate obtained out of band. Supplying it is what makes
   * the timestamp a third-party attestation rather than a self-signed claim.
   */
  pinnedCertPem?: string | undefined;
}

/**
 * Verify a timestamp token. Never throws for a malformed token — a token we
 * cannot parse is a verification failure with a reason, not a crash, because
 * this runs over attacker-supplied bytes from an anchors file.
 */
export function verifyTimeStampToken(
  tokenDer: Buffer,
  opts: VerifyTokenOptions,
): TokenVerification {
  const problems: string[] = [];
  const fail = (partial: Partial<TokenVerification> = {}): TokenVerification => ({
    ok: false,
    genTime: '',
    imprintOk: false,
    signatureOk: false,
    contentDigestOk: false,
    nonceOk: null,
    certPinned: false,
    certFingerprint: null,
    certSubject: null,
    certValidAtGenTime: null,
    hasTimestampingEku: null,
    tstInfo: null,
    problems,
    ...partial,
  });

  let parsed: ParsedToken;
  try {
    parsed = parseTimeStampToken(tokenDer);
  } catch (e) {
    problems.push(`token is not a well-formed RFC 3161 TimeStampToken: ${describe(e)}`);
    return fail();
  }

  const { tstInfo, eContent, certificates, signerInfo } = parsed;

  // 1. Is the timestamp over OUR digest? Without this the token may be genuine
  //    but about a completely different document.
  const imprintOk = timingSafeEqualBuffers(tstInfo.messageImprint, opts.expectedDigest);
  if (!imprintOk) {
    problems.push(
      `messageImprint mismatch: token covers ${tstInfo.messageImprint.toString('hex')}, expected ${opts.expectedDigest.toString('hex')}`,
    );
  }

  // 2. Replay check.
  let nonceOk: boolean | null = null;
  if (opts.expectedNonce) {
    nonceOk = tstInfo.nonce !== null && timingSafeEqualBuffers(tstInfo.nonce, opts.expectedNonce);
    if (!nonceOk) problems.push('nonce mismatch: the response does not answer our request');
  }

  // 3. signedAttrs must commit to the TSTInfo we just read, or the signature
  //    covers attributes that have nothing to do with this content.
  let contentDigestOk = false;
  if (!signerInfo.signedAttrsDer) {
    problems.push('signerInfo has no signed attributes (unsupported: cannot bind the content)');
  } else {
    const attr = signerInfo.signedAttrs.get(OID.attrMessageDigest)?.[0];
    if (!attr || attr.tag !== TAG.OCTET_STRING) {
      problems.push('signed attributes carry no messageDigest');
    } else {
      const expected = createHash(signerInfo.digestAlgorithm).update(eContent).digest();
      contentDigestOk = timingSafeEqualBuffers(Buffer.from(attr.content), expected);
      if (!contentDigestOk)
        problems.push('signed messageDigest does not match the TSTInfo content');
    }
    const ctAttr = signerInfo.signedAttrs.get(OID.attrContentType)?.[0];
    if (ctAttr) {
      try {
        if (readOid(ctAttr) !== OID.tstInfo)
          problems.push('signed contentType is not id-ct-TSTInfo');
      } catch {
        problems.push('signed contentType attribute is malformed');
      }
    }
  }

  // 4. Pick the signer certificate, then check the CMS signature under it.
  const signerCert = selectSignerCertificate(certificates, signerInfo);
  let signatureOk = false;
  let certFingerprint: string | null = null;
  let certSubject: string | null = null;
  let certValidAtGenTime: boolean | null = null;
  let hasTimestampingEku: boolean | null = null;

  if (!signerCert) {
    problems.push(
      certificates.length === 0
        ? 'the token embeds no certificate, so the signature cannot be checked offline (request one with certReq)'
        : 'no embedded certificate matches the signerInfo identifier',
    );
  } else {
    certFingerprint = signerCert.fingerprint256.replace(/:/g, '').toLowerCase();
    certSubject = signerCert.subject.replace(/\n/g, ', ');

    if (signerInfo.signedAttrsDer) {
      try {
        signatureOk = verifyCmsSignature(signerCert, signerInfo);
      } catch (e) {
        problems.push(`signature check failed: ${describe(e)}`);
      }
      if (!signatureOk && problems.every((p) => !p.startsWith('signature check failed'))) {
        problems.push('the TSA signature over the signed attributes is INVALID');
      }
    }

    // The ESS signing-certificate attribute, when present, pins which cert the
    // TSA meant. Ignoring it would let an attacker swap in another cert whose
    // key they hold and re-sign.
    const essProblem = checkEssSigningCertificate(signerCert, signerInfo);
    if (essProblem) problems.push(essProblem);

    const genTimeMs = Date.parse(tstInfo.genTime);
    if (!Number.isNaN(genTimeMs)) {
      const from = Date.parse(signerCert.validFrom);
      const to = Date.parse(signerCert.validTo);
      certValidAtGenTime = genTimeMs >= from && genTimeMs <= to;
      if (!certValidAtGenTime) {
        problems.push(
          `the signing certificate was not valid at genTime (${tstInfo.genTime} outside ${signerCert.validFrom} .. ${signerCert.validTo})`,
        );
      }
    }

    hasTimestampingEku = certHasTimestampingEku(signerCert);
    if (hasTimestampingEku === false) {
      problems.push(
        'the signing certificate does not carry the timeStamping extended key usage (RFC 3161 §2.3 requires it)',
      );
    }
  }

  // 5. The pin — the only check that makes any of the above mean something to
  //    a third party.
  let certPinned = false;
  if (opts.pinnedCertPem !== undefined) {
    let pinnedFingerprint: string | null = null;
    try {
      pinnedFingerprint = new X509Certificate(opts.pinnedCertPem).fingerprint256
        .replace(/:/g, '')
        .toLowerCase();
    } catch (e) {
      problems.push(`the pinned TSA certificate could not be parsed: ${describe(e)}`);
    }
    if (pinnedFingerprint) {
      certPinned = certFingerprint === pinnedFingerprint;
      if (!certPinned) {
        problems.push(
          `signer certificate does not match the pinned TSA certificate (token ${certFingerprint ?? 'none'}, pinned ${pinnedFingerprint})`,
        );
      }
    }
  }

  const ok = problems.length === 0 && imprintOk && signatureOk && contentDigestOk;
  return {
    ok,
    genTime: tstInfo.genTime,
    imprintOk,
    signatureOk,
    contentDigestOk,
    nonceOk,
    certPinned,
    certFingerprint,
    certSubject,
    certValidAtGenTime,
    hasTimestampingEku,
    tstInfo,
    problems,
  };
}

/** Match the signerInfo's IssuerAndSerialNumber against the embedded certs. */
function selectSignerCertificate(
  certificates: X509Certificate[],
  signerInfo: SignerInfo,
): X509Certificate | null {
  if (certificates.length === 0) return null;
  if (!signerInfo.sid) return certificates[0] ?? null;

  for (const cert of certificates) {
    try {
      const tbs = childAt(parseDer(Buffer.from(cert.raw)), 0, TAG.SEQUENCE);
      const kids = children(tbs);
      // tbsCertificate ::= { [0] version DEFAULT v1, serialNumber, signature,
      //                      issuer, validity, subject, spki, ... }
      const base = kids[0]?.tag === contextTag(0) ? 1 : 0;
      const serial = kids[base];
      const issuer = kids[base + 2];
      if (!serial || !issuer) continue;
      if (
        Buffer.from(serial.raw).equals(signerInfo.sid.serialDer) &&
        Buffer.from(issuer.raw).equals(signerInfo.sid.issuerDer)
      ) {
        return cert;
      }
    } catch {
      continue;
    }
  }
  return null;
}

/** Verify the CMS signature over the re-tagged signedAttrs. */
function verifyCmsSignature(cert: X509Certificate, signerInfo: SignerInfo): boolean {
  const data = signerInfo.signedAttrsDer;
  if (!data) return false;
  // `cert.publicKey` is already a public KeyObject — passing it back through
  // createPublicKey() throws, because that overload expects a private key.
  const key = cert.publicKey;
  const oid = signerInfo.signatureAlgorithmOid;

  switch (oid) {
    case OID.ed25519:
      // Ed25519 signs the message directly; no external digest.
      return verify(null, data, key, signerInfo.signature);

    case OID.sha256WithRsa:
      return verify('sha256', data, key, signerInfo.signature);
    case OID.sha384WithRsa:
      return verify('sha384', data, key, signerInfo.signature);
    case OID.sha512WithRsa:
      return verify('sha512', data, key, signerInfo.signature);
    case OID.sha1WithRsa:
      return verify('sha1', data, key, signerInfo.signature);

    case OID.ecdsaWithSha256:
      return verify('sha256', data, key, signerInfo.signature);
    case OID.ecdsaWithSha384:
      return verify('sha384', data, key, signerInfo.signature);
    case OID.ecdsaWithSha512:
      return verify('sha512', data, key, signerInfo.signature);

    case OID.rsaEncryption:
      // Bare rsaEncryption: the digest comes from signerInfo.digestAlgorithm.
      return verify(signerInfo.digestAlgorithm, data, key, signerInfo.signature);

    case OID.rsaPss: {
      const hash = pssHashName(signerInfo.signatureAlgorithmParams) ?? signerInfo.digestAlgorithm;
      return verify(
        hash,
        data,
        {
          key,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_AUTO,
        },
        signerInfo.signature,
      );
    }

    default:
      throw new Asn1Error(`unsupported signature algorithm OID ${oid}`);
  }
}

/** RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm DEFAULT sha1, ... }. */
function pssHashName(params: Asn1Node | undefined): HashName | null {
  if (!params || params.tag !== TAG.SEQUENCE) return null;
  const hashNode = findChild(params, contextTag(0));
  if (!hashNode) return null;
  try {
    return (
      DIGEST_BY_OID.get(readOid(childAt(childAt(hashNode, 0, TAG.SEQUENCE), 0, TAG.OID))) ?? null
    );
  } catch {
    return null;
  }
}

/**
 * ESS signing-certificate binding (RFC 2634 / RFC 5035). Returns a problem
 * string, or null when absent or matching.
 */
function checkEssSigningCertificate(cert: X509Certificate, signerInfo: SignerInfo): string | null {
  const v2 = signerInfo.signedAttrs.get(OID.attrSigningCertificateV2)?.[0];
  const v1 = signerInfo.signedAttrs.get(OID.attrSigningCertificate)?.[0];
  const attr = v2 ?? v1;
  if (!attr) return null;
  try {
    // SigningCertificate[V2] ::= SEQUENCE { certs SEQUENCE OF ESSCertID[V2], ... }
    const certsSeq = childAt(attr, 0, TAG.SEQUENCE);
    const first = children(certsSeq)[0];
    if (!first) return null;
    const parts = children(first);
    // ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash OCTET STRING, ... }
    // ESSCertID   ::= SEQUENCE { certHash OCTET STRING (sha1), issuerSerial OPTIONAL }
    let hashName: HashName = v2 ? 'sha256' : 'sha1';
    let hashNode = parts[0];
    if (hashNode?.tag === TAG.SEQUENCE) {
      hashName = DIGEST_BY_OID.get(readOid(childAt(hashNode, 0, TAG.OID))) ?? hashName;
      hashNode = parts[1];
    }
    if (!hashNode || hashNode.tag !== TAG.OCTET_STRING) return null;
    const actual = createHash(hashName).update(Buffer.from(cert.raw)).digest();
    return timingSafeEqualBuffers(Buffer.from(hashNode.content), actual)
      ? null
      : 'the ESS signing-certificate attribute names a different certificate than the one embedded';
  } catch {
    return 'the ESS signing-certificate attribute is malformed';
  }
}

/** null when the extension is absent (older TSAs omit it). */
function certHasTimestampingEku(cert: X509Certificate): boolean | null {
  try {
    const tbs = childAt(parseDer(Buffer.from(cert.raw)), 0, TAG.SEQUENCE);
    const kids = children(tbs);
    const extsNode = kids.find((c) => c.tag === contextTag(3));
    if (!extsNode) return null;
    const exts = children(childAt(extsNode, 0, TAG.SEQUENCE));
    for (const ext of exts) {
      const extKids = children(ext);
      if (!extKids[0] || readOid(extKids[0]) !== '2.5.29.37') continue; // id-ce-extKeyUsage
      const value = extKids.find((c) => c.tag === TAG.OCTET_STRING);
      if (!value) return null;
      const usages = children(parseDer(Buffer.from(value.content)));
      // id-kp-timeStamping
      return usages.some((u) => u.tag === TAG.OID && readOid(u) === '1.3.6.1.5.5.7.3.8');
    }
    return null;
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* Network                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * POST a TimeStampReq to a TSA. This is the ONLY function in this module that
 * touches the network, and nothing calls it unless the operator passed an
 * explicit `--tsa <url>`; traceglass makes no outbound request by default.
 *
 * What crosses the wire is the request DER: a version number, an algorithm OID,
 * a nonce, and one SHA-256 digest. No run content of any kind.
 */
export async function requestTimestamp(
  tsaUrl: string,
  request: TimeStampRequest,
  opts: { timeoutMs?: number; headers?: Record<string, string> } = {},
): Promise<{ response: TimeStampResponse; raw: Buffer }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), opts.timeoutMs ?? 15_000);
  let res: Response;
  try {
    res = await fetch(tsaUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/timestamp-query',
        accept: 'application/timestamp-reply',
        ...opts.headers,
      },
      body: new Uint8Array(request.der),
      signal: controller.signal,
    });
  } catch (e) {
    const reason = e instanceof Error && e.name === 'AbortError' ? 'timed out' : describe(e);
    throw new Error(`TSA request to ${tsaUrl} failed: ${reason}`);
  } finally {
    clearTimeout(timeout);
  }

  const raw = Buffer.from(await res.arrayBuffer());
  if (!res.ok) {
    throw new Error(`TSA ${tsaUrl} returned HTTP ${res.status} ${res.statusText}`);
  }
  let response: TimeStampResponse;
  try {
    response = parseTimeStampResponse(raw);
  } catch (e) {
    throw new Error(`TSA ${tsaUrl} returned an unparseable response: ${describe(e)}`);
  }
  // 0 = granted, 1 = grantedWithMods. Anything else carries no usable token.
  if (response.status !== 0 && response.status !== 1) {
    const detail = [response.statusText.join('; '), response.failInfo.join(', ')]
      .filter(Boolean)
      .join(' — ');
    throw new Error(
      `TSA ${tsaUrl} refused the request: ${response.statusName}${detail ? ` (${detail})` : ''}`,
    );
  }
  if (!response.tokenDer) {
    throw new Error(`TSA ${tsaUrl} returned ${response.statusName} but no timestamp token`);
  }
  return { response, raw };
}

function timingSafeEqualBuffers(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && a.equals(b);
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
