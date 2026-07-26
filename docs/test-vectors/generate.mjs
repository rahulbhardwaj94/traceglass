/**
 * Regenerate the frozen test-vector corpus from the CURRENT implementation.
 *
 *   npm run build && node docs/test-vectors/generate.mjs
 *
 * This script is a development tool, not part of the published format. It
 * imports the real @traceglass/core build so the vectors are observed, never
 * guessed. `check.mjs` then re-derives the same values from an INDEPENDENT
 * reference implementation written only from SPEC.md — if the two disagree,
 * either the spec or the implementation is wrong.
 *
 * Everything here is deterministic: fixed ids, timestamps, salts, spans, and a
 * fixed (publicly published, TEST ONLY) Ed25519 key. Ed25519 is deterministic
 * per RFC 8032, so re-running produces byte-identical output.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CORE = join(HERE, '..', '..', 'packages', 'core', 'dist');

const { canonicalize, canonicalStep, hashStep, computeRunHash } = await import(
  join(CORE, 'integrity/hash.js')
);
const { commitmentFor, walkLeaves } = await import(join(CORE, 'redact/commit.js'));
const { signaturePayload, keyIdFromPublicKey, signRun, redactionsHash, redactionSealPayload } =
  await import(join(CORE, 'integrity/signing.js'));

/**
 * EVERY call into core below passes its hash version EXPLICITLY.
 *
 * The version-1 corpus is frozen: those files are the format as published in
 * 0.3.0–0.8.0 and re-running this script must reproduce them byte-for-byte. If
 * these calls relied on the library defaults, a future default change would
 * silently rewrite the frozen vectors — which is exactly the failure this whole
 * versioning exercise exists to prevent.
 */
const V1 = 1;
const V2 = 2;

/** The v2 preimage separator, U+0000. Written this way so no source file carries a raw NUL. */
const NUL = String.fromCharCode(0);

const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const write = (rel, obj) => {
  const p = join(HERE, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
  console.log('wrote', rel);
};

/* ------------------------------------------------------------------ */
/* 01 — canonicalization                                               */
/* ------------------------------------------------------------------ */

// Each vector's input is given as JSON *text*, so it is unambiguous across
// languages (including lone surrogates and raw control characters).
const canonicalCases = [
  ['scalar-string', '"hello"', 'A bare string is a valid canonical input.'],
  ['scalar-null', 'null', ''],
  ['scalar-true', 'true', ''],
  ['empty-object', '{}', ''],
  ['empty-array', '[]', ''],
  ['key-order-ascii', '{"b":1,"a":2,"A":3,"_":4,"0":5}', 'Keys sort by UTF-16 code unit.'],
  [
    'key-order-nested',
    '{"z":{"y":1,"x":2},"a":[{"q":1,"p":2}]}',
    'Sorting recurses; array order is preserved.',
  ],
  [
    'key-order-array-index',
    '{"10":1,"2":2,"1":3}',
    'ARRAY-INDEX KEYS SORT NUMERICALLY, NOT LEXICOGRAPHICALLY. A naive "sort all keys as strings" implementation produces {"1":3,"10":1,"2":2} and a different hash. See SPEC.md §4.2.2.',
  ],
  [
    'key-order-index-vs-string',
    '{"b":1,"10":2,"a":3,"2":4,"01":5,"-1":6,"1.5":7,"4294967295":8,"4294967294":9}',
    'Array-index keys (2, 10, 4294967294) come FIRST in numeric order; everything else — including "01", "-1", "1.5" and 4294967295 (= 2**32-1, deliberately NOT an index) — follows in UTF-16 order.',
  ],
  [
    'key-order-big-numeric',
    '{"99999999999999999999":1,"b":2,"3":3}',
    'Only 3 is an array index; the 20-digit key is an ordinary string key.',
  ],
  ['key-empty-string', '{"":1,"a":2}', 'The empty key sorts first among non-index keys.'],
  [
    'key-order-astral',
    '{"\\ud83d\\ude00":1,"\\ufffd":2,"\\ue000":3}',
    'U+1F600 sorts BEFORE U+E000 and U+FFFD because sorting is on UTF-16 code units (lead surrogate U+D83D), not code points. Any implementation sorting by code point produces a DIFFERENT hash here.',
  ],
  ['null-value-kept', '{"a":null}', 'null is a value and is retained.'],
  ['array-with-null', '[null,1,"x"]', ''],
  ['nested-empties', '{"a":{},"b":[],"c":[[]]}', ''],
  [
    'array-order-preserved',
    '[3,1,2]',
    'Arrays are ordered data; they are never sorted.',
  ],
  // --- unicode ---
  ['unicode-nfc', '"caf\\u00e9"', 'Precomposed e-acute (NFC).'],
  [
    'unicode-nfd',
    '"cafe\\u0301"',
    'Decomposed e + combining acute (NFD). Canonically DISTINCT from the NFC vector above: no Unicode normalization is applied.',
  ],
  ['unicode-emoji-zwj', '"\\ud83d\\udc69\\u200d\\ud83d\\ude80"', 'Woman astronaut: ZWJ sequence.'],
  ['unicode-devanagari', '"\\u0928\\u092e\\u0938\\u094d\\u0924\\u0947"', ''],
  [
    'unicode-lone-surrogate',
    '"\\ud800"',
    'An unpaired surrogate is emitted as a \\udXXX escape (well-formed JSON.stringify, ES2019).',
  ],
  [
    'string-escapes',
    '"\\"\\\\/\\b\\f\\n\\r\\t"',
    'Two-char escapes are used where they exist. Solidus is NOT escaped.',
  ],
  [
    'string-controls',
    '"\\u0000\\u001f\\u007f"',
    'C0 controls are escaped as \\u00XX; U+007F (DEL) is emitted RAW.',
  ],
  [
    'string-line-separators',
    '"\\u2028\\u2029"',
    'U+2028/U+2029 are emitted RAW, not escaped.',
  ],
  ['string-nbsp', '"\\u00a0"', ''],
  // --- numbers: the sharp edges ---
  ['number-int-zero', '0', ''],
  ['number-int', '100', ''],
  [
    'number-int-trailing-zero',
    '100.0',
    'An integral value loses its ".0": canonical form is "100".',
  ],
  ['number-negative-zero', '-0.0', 'Negative zero canonicalizes to "0".'],
  ['number-simple-float', '4.7', 'The README cost example.'],
  [
    'number-binary-artifact',
    '0.30000000000000004',
    'The value of 0.1+0.2. Shortest round-trip repr, all 17 digits.',
  ],
  ['number-cent', '0.01', ''],
  ['number-1e-4', '0.0001', 'Last magnitude where JS and Python agree.'],
  [
    'number-1e-5',
    '0.00001',
    'JS emits fixed "0.00001"; Python json.dumps emits "1e-05". FIRST DIVERGENCE.',
  ],
  ['number-1e-6', '0.000001', 'JS "0.000001"; Python "1e-06".'],
  ['number-1e-7', '1e-7', 'JS "1e-7"; Python "1e-07" (zero-padded exponent).'],
  ['number-micro-cost', '0.000025', 'A realistic per-token cost. JS "0.000025"; Python "2.5e-05".'],
  ['number-1e21', '1e21', 'JS switches to exponential at 1e21: "1e+21".'],
  ['number-1e20', '1e20', 'Still fixed notation: "100000000000000000000".'],
  ['number-denormal-min', '5e-324', 'Smallest positive double.'],
  ['number-max-safe-int', '9007199254740991', ''],
  [
    'number-beyond-max-safe-int',
    '9007199254740993',
    'Not representable as a double; canonicalizes to 9007199254740992. A verifier using arbitrary-precision integers gets a DIFFERENT answer.',
  ],
  ['number-large-float', '1.2345678901234567e300', ''],
  ['number-negative', '-4.7', ''],
  [
    'number-huge-literal',
    '123456789012345678901234567890',
    'Parsed as a double, so canonicalizes to 1.2345678901234568e+29.',
  ],
  // --- realistic payload shapes ---
  [
    'payload-tool-args',
    '{"query":"SELECT * FROM users WHERE id = 42","timeout_ms":3000,"retries":0}',
    '',
  ],
  [
    'payload-nested',
    '{"result":{"rows":[{"id":1,"name":"\\u00c5sa"},{"id":2,"name":"\\ud83c\\udf3f"}],"count":2},"cached":false}',
    '',
  ],
];

const canonicalVectors = canonicalCases.map(([name, inputJson, note]) => {
  const value = JSON.parse(inputJson);
  const canonical = canonicalize(value);
  return { name, note, inputJson, canonical, sha256: sha256hex(canonical) };
});

write('01-canonical.json', {
  about:
    'Canonicalization vectors. Parse `inputJson` as JSON, canonicalize the resulting value, and you MUST get `canonical` byte-for-byte; sha256 of its UTF-8 bytes MUST equal `sha256`.',
  hashVersion: 1,
  vectors: canonicalVectors,
});

/* ------------------------------------------------------------------ */
/* 02 — leaf walking + commitments                                     */
/* ------------------------------------------------------------------ */

const walkCases = [
  ['scalar', 'input', '"hello"'],
  ['null', 'input', 'null'],
  ['nested-object', 'input', '{"a":{"b":1}}'],
  ['array', 'input', '["x","y"]'],
  ['array-of-arrays', 'input', '[[1,2],[3]]'],
  ['object-numeric-keys', 'input', '{"0":"x","1":"y"}'],
  ['empty-object-is-a-leaf', 'input', '{}'],
  ['empty-array-is-a-leaf', 'input', '[]'],
  ['nested-empties-are-leaves', 'input', '{"a":{},"b":[]}'],
  ['mixed', 'output', '{"rows":[{"id":1},{"id":2}],"ok":true}'],
  [
    'AMBIGUOUS-dotted-key',
    'input',
    '{"a.b":1}',
    'Produces the SAME path "input.a.b" as {"a":{"b":1}}. See SPEC.md §9.3 — this is a known defect: such a leaf CANNOT be re-verified.',
  ],
  [
    'AMBIGUOUS-empty-key',
    'input',
    '{"":1}',
    'Produces path "input." which does not resolve on read-back. Known defect.',
  ],
  [
    'AMBIGUOUS-bracket-key',
    'input',
    '{"a[0]":1}',
    'Produces path "input.a[0]", indistinguishable from {"a":[1]}. Known defect.',
  ],
];

const walkVectorsFor = (version) =>
  walkCases.map(([name, field, inputJson, note]) => {
    const leaves = [];
    walkLeaves(
      JSON.parse(inputJson),
      (path, leaf) => leaves.push({ path, canonicalLeaf: canonicalize(leaf) }),
      field,
      version,
    );
    return { name, note: note ?? '', field, inputJson, leaves };
  });
const walkVectors = walkVectorsFor(V1);

// Fixed salts: 16 bytes of the byte value equal to the index, hex-encoded.
const fixedSalt = (i) => Buffer.alloc(16, i).toString('hex');

const commitmentVectors = [
  ['string', '"alice@example.com"'],
  ['number', '4.7'],
  ['micro-number', '0.000025'],
  ['bool', 'true'],
  ['null', 'null'],
  ['empty-object', '{}'],
  ['empty-array', '[]'],
  ['emoji', '"\\ud83c\\udf3f"'],
  ['nfd', '"cafe\\u0301"'],
  ['redaction-marker', '"[traceglass:redacted]"'],
].map(([name, valueJson], i) => {
  const salt = fixedSalt(i + 1);
  const value = JSON.parse(valueJson);
  return {
    name,
    salt,
    valueJson,
    canonicalValue: canonicalize(value),
    preimage: salt + canonicalize(value),
    commitment: commitmentFor(salt, value),
  };
});

write('02-commitments.json', {
  about:
    'Leaf-walking paths and per-leaf commitments. commitment = sha256_hex(salt_ascii || canonical(value)), concatenated as UTF-8 text.',
  hashVersion: 1,
  walk: walkVectors,
  commitments: commitmentVectors,
});

/* ------------------------------------------------------------------ */
/* 03/04 — steps and runs                                              */
/* ------------------------------------------------------------------ */

const T0 = '2026-07-25T09:00:00.000Z';

/** Build commitments over a payload with deterministic salts. */
function deterministicCommitments(payload, saltSeed, version) {
  const commitments = {};
  const salts = {};
  let n = 0;
  for (const field of ['input', 'output', 'dataPayload']) {
    if (payload[field] === undefined) continue;
    walkLeaves(
      payload[field],
      (path, leaf) => {
        const salt = createHash('sha256')
          .update(`${saltSeed}|${path}|${n++}`)
          .digest('hex')
          .slice(0, 32);
        salts[path] = salt;
        commitments[path] = commitmentFor(salt, leaf);
      },
      field,
      version,
    );
  }
  return { commitments, salts };
}

function chain(steps, version) {
  let prevHash = '';
  return steps.map((s) => {
    const withPrev = { ...s, prevHash, hash: '' };
    const hash = hashStep(withPrev, prevHash, version);
    prevHash = hash;
    return { ...withPrev, hash };
  });
}

function totalsOf(steps) {
  return steps.reduce(
    (a, s) => ({
      tokens: a.tokens + s.tokens,
      cost: a.cost + s.cost,
      durationMs: a.durationMs + s.durationMs,
      steps: a.steps + 1,
    }),
    { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
  );
}

function makeRun(id, name, rawSteps, version = V1) {
  const steps = chain(rawSteps, version);
  const partial = {
    id,
    name,
    startedAt: T0,
    endedAt: '2026-07-25T09:00:10.000Z',
    status: 'completed',
    currency: 'INR',
    totals: totalsOf(steps),
    warnings: [],
    steps,
    runHash: '',
    ...(version === V1 ? {} : { hashVersion: version }),
  };
  return { ...partial, runHash: computeRunHash(partial) };
}

const envelope = (run) => ({ formatVersion: 1, exportedAt: T0, run });

// --- vector run 1: minimal, no commitments (pre-0.6 hashing shape) --------
const minimalSteps = [
  {
    id: 'vec-min:0',
    runId: 'vec-min',
    index: 0,
    type: 'user_input',
    label: 'User request',
    startedAt: T0,
    durationMs: 0,
    tokens: 0,
    cost: 0,
    input: 'Summarise Q3 spend',
    spanId: '00000000000000a1',
  },
  {
    id: 'vec-min:1',
    runId: 'vec-min',
    index: 1,
    type: 'final_output',
    label: 'Answer',
    startedAt: '2026-07-25T09:00:05.000Z',
    durationMs: 5000,
    tokens: 1280,
    cost: 4.7,
    output: { text: 'Q3 spend was 4.7 lakh.' },
    spanId: '00000000000000a2',
    parentSpanId: '00000000000000a1',
  },
];
const minimalRun = makeRun('vec-min', 'minimal run', minimalSteps);

// --- vector run 2: with commitments, tricky payload -----------------------
const trickyPayload = {
  input: {
    query: 'SELECT * FROM payments WHERE id = 42',
    unicode: { nfc: 'café', nfd: 'café', emoji: '👩‍🚀' },
    empties: { obj: {}, arr: [] },
    numbers: { cost: 4.7, micro: 0.000025, big: 9007199254740991, drift: 0.1 + 0.2 },
    rows: [{ id: 1 }, { id: 2 }],
  },
  output: { ok: true, note: null },
};
const committedSteps = [
  {
    id: 'vec-cm:0',
    runId: 'vec-cm',
    index: 0,
    type: 'tool_call',
    label: 'Tool: db_query',
    startedAt: T0,
    durationMs: 120,
    tokens: 0,
    cost: 0.000025,
    toolName: 'db_query',
    ...trickyPayload,
    spanId: '00000000000000b1',
    ...deterministicCommitments(trickyPayload, 'vec-cm:0', V1),
  },
];
const committedRun = makeRun('vec-cm', 'committed run', committedSteps);

// --- vector run 3: same run with one leaf redacted ------------------------
const redactedStep = structuredClone(committedRun.steps[0]);
const REDACTED_MARKER = '[traceglass:redacted]';
redactedStep.input.query = REDACTED_MARKER;
delete redactedStep.salts['input.query'];
redactedStep.redactions = [
  { path: 'input.query', at: '2026-07-25T10:00:00.000Z', reason: 'gdpr-erasure', by: 'manual' },
];
const redactedRun = {
  ...committedRun,
  id: 'vec-cm',
  steps: [redactedStep],
  // runHash deliberately UNCHANGED — that is the property under test.
  runHash: committedRun.runHash,
};

// --- vector run 4: signed -------------------------------------------------
const privateKeyPem = readFileSync(join(HERE, 'keys', 'test-private.pem'), 'utf8');
const publicKeyPem = readFileSync(join(HERE, 'keys', 'test-public.pem'), 'utf8');
const SIGNED_AT = '2026-07-25T09:00:11.000Z';
const signedRun = signRun(minimalRun, privateKeyPem, publicKeyPem);
signedRun.signature.signedAt = SIGNED_AT; // pin the timestamp, then re-sign below
{
  const { sign, createPrivateKey } = await import('node:crypto');
  signedRun.signature.signature = sign(
    null,
    Buffer.from(signaturePayload(signedRun.id, signedRun.runHash, SIGNED_AT), 'utf8'),
    createPrivateKey(privateKeyPem),
  ).toString('base64');
}

write('04-runs/minimal.tgev.json', envelope(minimalRun));
write('04-runs/committed.tgev.json', envelope(committedRun));
write('04-runs/redacted.tgev.json', envelope(redactedRun));
write('04-runs/signed.tgev.json', envelope(signedRun));

const stepExpectations = (run) =>
  run.steps.map((s) => ({
    id: s.id,
    index: s.index,
    prevHash: s.prevHash,
    canonicalStep: canonicalStep(s, V1),
    hashPreimage: canonicalStep(s, V1) + s.prevHash,
    hash: s.hash,
  }));

write('03-steps.json', {
  about:
    'Step canonical forms and chain hashes. hash = sha256_hex(canonicalStep(step) || prevHash), UTF-8. `canonicalStep` covers only the hashed fields; when commitments exist they replace the raw payload field.',
  hashVersion: 1,
  runs: {
    minimal: stepExpectations(minimalRun),
    committed: stepExpectations(committedRun),
    redacted: stepExpectations(redactedRun),
  },
});

write('05-signature.json', {
  about:
    'Ed25519 signature over canonicalize({runId, runHash, signedAt}). The key below is PUBLISHED and TEST ONLY.',
  hashVersion: 1,
  publicKeyPem,
  keyId: keyIdFromPublicKey(publicKeyPem),
  runId: signedRun.id,
  runHash: signedRun.runHash,
  signedAt: SIGNED_AT,
  signaturePayload: signaturePayload(signedRun.id, signedRun.runHash, SIGNED_AT),
  signatureBase64: signedRun.signature.signature,
});

/* ------------------------------------------------------------------ */
/* 06 — tgcanon/2                                                      */
/* ------------------------------------------------------------------ */

/*
 * The v2 corpus is ADDITIVE. Nothing above changes: the files an auditor
 * already holds are version 1 and stay exactly as they are. What follows pins
 * the three things v2 alters — escaped commitment paths, the domain-separated
 * step preimage with `runId` in it, and the run-header anchor — plus the
 * redaction seal that the version-2 erasure rules lean on.
 */

// Payload built specifically from the keys that BREAK version 1 (SPEC §12.5):
// a literal dot, a literal bracket, a backslash, and the empty key.
const v2NastyPayload = {
  input: {
    'user.email': 'alice@example.com',
    'rows[0]': 'not an array',
    'a\\b': 1,
    '': 'empty key',
    user: { email: 'nested, and a DIFFERENT leaf from user.email above' },
    rows: [{ id: 1 }],
  },
  output: { ok: true },
};

const v2Steps = [
  {
    id: 'vec-v2:0',
    runId: 'vec-v2',
    index: 0,
    type: 'tool_call',
    label: 'Tool: db_query',
    startedAt: T0,
    durationMs: 120,
    tokens: 40,
    cost: 0.000025,
    toolName: 'db_query',
    ...v2NastyPayload,
    spanId: '00000000000000c1',
    ...deterministicCommitments(v2NastyPayload, 'vec-v2:0', V2),
  },
  {
    id: 'vec-v2:1',
    runId: 'vec-v2',
    index: 1,
    type: 'final_output',
    label: 'Answer',
    startedAt: '2026-07-25T09:00:05.000Z',
    durationMs: 5000,
    tokens: 1280,
    cost: 4.7,
    output: { text: 'Q3 spend was 4.7 lakh.' },
    spanId: '00000000000000c2',
    parentSpanId: '00000000000000c1',
  },
];
const v2Run = makeRun('vec-v2', 'v2 run', v2Steps, V2);

// --- v2 run, signed --------------------------------------------------------
const V2_SIGNED_AT = '2026-07-25T09:00:11.000Z';
const { sign, createPrivateKey } = await import('node:crypto');
const v2SignedRun = {
  ...v2Run,
  signature: {
    algorithm: 'ed25519',
    keyId: keyIdFromPublicKey(publicKeyPem),
    publicKey: publicKeyPem,
    signature: sign(
      null,
      Buffer.from(signaturePayload(v2Run.id, v2Run.runHash, V2_SIGNED_AT), 'utf8'),
      createPrivateKey(privateKeyPem),
    ).toString('base64'),
    signedAt: V2_SIGNED_AT,
  },
};

// --- v2 run, one leaf redacted AND sealed ----------------------------------
// The redacted path is the dotted key, escaped — the exact leaf version 1 could
// neither verify nor address.
const V2_REDACTED_PATH = 'input.user\\.email';
const v2RedactedStep = structuredClone(v2SignedRun.steps[0]);
v2RedactedStep.input['user.email'] = REDACTED_MARKER;
delete v2RedactedStep.salts[V2_REDACTED_PATH];
v2RedactedStep.redactions = [
  { path: V2_REDACTED_PATH, at: '2026-07-25T10:00:00.000Z', reason: 'gdpr-erasure', by: 'manual' },
];
const v2RedactedRun = {
  ...v2SignedRun,
  steps: [v2RedactedStep, v2SignedRun.steps[1]],
  // Anchor deliberately UNCHANGED — still the property under test in v2.
  runHash: v2SignedRun.runHash,
};

const V2_SEALED_AT = '2026-07-25T10:00:01.000Z';
const v2RedactionsHash = redactionsHash(v2RedactedRun);
const v2SealedRun = {
  ...v2RedactedRun,
  redactionSeal: {
    algorithm: 'ed25519',
    keyId: keyIdFromPublicKey(publicKeyPem),
    publicKey: publicKeyPem,
    signature: sign(
      null,
      Buffer.from(
        redactionSealPayload(v2RedactedRun.id, v2RedactedRun.runHash, v2RedactionsHash, V2_SEALED_AT),
        'utf8',
      ),
      createPrivateKey(privateKeyPem),
    ).toString('base64'),
    sealedAt: V2_SEALED_AT,
    redactionsHash: v2RedactionsHash,
  },
};

write('04-runs/v2-signed.tgev.json', envelope(v2SignedRun));
write('04-runs/v2-redacted-sealed.tgev.json', envelope(v2SealedRun));

const v2StepExpectations = (run) =>
  run.steps.map((s) => ({
    id: s.id,
    index: s.index,
    prevHash: s.prevHash,
    canonicalStep: canonicalStep(s, V2),
    // NUL (U+0000) separates the tag, the canonical form and the prevHash.
    // Shown escaped here; it is a single byte 0x00 on the wire.
    hashPreimageEscaped: JSON.stringify(
      `tgstep/2${NUL}${canonicalStep(s, V2)}${NUL}${s.prevHash}`,
    ),
    hash: s.hash,
  }));

write('06-v2.json', {
  about:
    'tgcanon/2 vectors. ADDITIVE: the version-1 files are unchanged and still normative for records that declare no hashVersion. See SPEC.md §15.',
  hashVersion: 2,
  walk: walkVectorsFor(V2),
  runs: {
    'v2-signed': v2StepExpectations(v2SignedRun),
    'v2-redacted-sealed': v2StepExpectations(v2SealedRun),
  },
  runHash: {
    about:
      'runHash = sha256_hex("tgrun/2" || NUL || canonical(header)). The header is the object below verbatim; `chainAnchor` is the final step hash.',
    header: {
      hashVersion: 2,
      id: v2Run.id,
      name: v2Run.name,
      startedAt: v2Run.startedAt,
      endedAt: v2Run.endedAt,
      status: v2Run.status,
      currency: v2Run.currency,
      totals: v2Run.totals,
      stepCount: v2Run.steps.length,
      chainAnchor: v2Run.steps[v2Run.steps.length - 1].hash,
    },
    runHash: v2Run.runHash,
  },
  signature: {
    keyId: keyIdFromPublicKey(publicKeyPem),
    signedAt: V2_SIGNED_AT,
    signaturePayload: signaturePayload(v2Run.id, v2Run.runHash, V2_SIGNED_AT),
    signatureBase64: v2SignedRun.signature.signature,
  },
  redactionSeal: {
    about:
      'redactionsHash = sha256_hex("tgredact/2" || NUL || canonical(log)), where `log` is the array below: one entry per step that has redactions, in step order. The seal signs canonical({runId, runHash, redactionsHash, sealedAt}).',
    log: v2SealedRun.steps
      .filter((s) => s.redactions && s.redactions.length > 0)
      .map((s) => ({ stepId: s.id, redactions: s.redactions })),
    redactionsHash: v2RedactionsHash,
    sealedAt: V2_SEALED_AT,
    sealPayload: redactionSealPayload(
      v2RedactedRun.id,
      v2RedactedRun.runHash,
      v2RedactionsHash,
      V2_SEALED_AT,
    ),
    signatureBase64: v2SealedRun.redactionSeal.signature,
    redactedPath: V2_REDACTED_PATH,
  },
});

console.log('\nanchors:');
console.log('  minimal  ', minimalRun.runHash);
console.log('  committed', committedRun.runHash);
console.log('  redacted ', redactedRun.steps[0].hash, '(must equal committed)');
console.log('  v2       ', v2Run.runHash);
console.log('  v2 sealed', v2SealedRun.runHash, '(must equal v2)');
