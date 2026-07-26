/**
 * Conformance harness for the traceglass evidence format.
 *
 *   node docs/test-vectors/check.mjs
 *
 * This file deliberately imports NOTHING from @traceglass/core. Every rule
 * below is re-implemented from the prose in SPEC.md — string escaping, key
 * ordering, number formatting, the hashed-field list, commitment substitution,
 * the chain rule and the verification algorithm. If this agrees with the
 * frozen vectors (which were generated from the real implementation), then the
 * spec is sufficient to build an independent verifier. If it disagrees, either
 * SPEC.md is wrong or the implementation drifted.
 *
 * Only node:crypto is used, for SHA-256 and Ed25519 — primitives, not format.
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const load = (f) => JSON.parse(readFileSync(join(HERE, f), 'utf8'));

/* ================================================================== *
 * Reference implementation of tgcanon/1 (SPEC.md §4)                  *
 * ================================================================== */

/** SPEC §4.4 — numbers. */
function canonNumber(n) {
  if (!Number.isFinite(n)) return 'null'; // §4.4.4
  if (Object.is(n, -0)) return '0'; // §4.4.3
  return String(n); // ECMAScript Number::toString, §4.4.1
}

/** SPEC §4.3 — strings. */
const TWO_CHAR = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r', 34: '\\"', 92: '\\\\' };
function canonString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (TWO_CHAR[c] !== undefined) {
      out += TWO_CHAR[c];
    } else if (c < 0x20) {
      out += '\\u' + c.toString(16).padStart(4, '0');
    } else if (c >= 0xd800 && c <= 0xdbff) {
      // lead surrogate: keep the pair raw only if it is well formed
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        out += s[i] + s[i + 1];
        i++;
      } else {
        out += '\\u' + c.toString(16).padStart(4, '0');
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      out += '\\u' + c.toString(16).padStart(4, '0'); // unpaired trail surrogate
    } else {
      out += s[i];
    }
  }
  return out + '"';
}

/** SPEC §4.2 — object key ordering: ascending UTF-16 code unit sequence. */
function utf16Compare(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/**
 * SPEC §4.2.2 — an "array-index key": the canonical decimal form of an integer
 * in [0, 2**32 - 2]. These sort FIRST, numerically, ahead of every other key.
 */
function isArrayIndexKey(k) {
  if (!/^(0|[1-9][0-9]*)$/.test(k)) return false;
  const n = Number(k);
  return Number.isInteger(n) && n <= 4294967294 && String(n) === k;
}

/** SPEC §4.2 — the full two-bucket ordering. */
function orderKeys(keys) {
  const idx = keys.filter(isArrayIndexKey).sort((a, b) => Number(a) - Number(b));
  const rest = keys.filter((k) => !isArrayIndexKey(k)).sort(utf16Compare);
  return [...idx, ...rest];
}

/** SPEC §4 — returns a string, or undefined for a value with no encoding. */
function canonicalize(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') return canonNumber(v);
  if (t === 'string') return canonString(v);
  if (t === 'undefined' || t === 'function' || t === 'symbol') return undefined; // §4.5
  if (Array.isArray(v)) return '[' + v.map((x) => canonicalize(x) ?? 'null').join(',') + ']';
  if (t === 'object') {
    const keys = orderKeys(Object.keys(v));
    const parts = [];
    for (const k of keys) {
      const enc = canonicalize(v[k]);
      if (enc === undefined) continue; // §4.5: absent members are omitted
      parts.push(canonString(k) + ':' + enc);
    }
    return '{' + parts.join(',') + '}';
  }
  return undefined;
}

/* ================================================================== *
 * Step hashing (SPEC §5) and commitments (SPEC §8)                    *
 * ================================================================== */

const HASHED_FIELDS = [
  'id', 'index', 'type', 'label', 'startedAt', 'durationMs', 'tokens', 'cost',
  'toolName', 'input', 'output', 'dataPayload', 'spanId', 'parentSpanId',
];
/** SPEC §15.2 — tgcanon/2 adds runId. */
const HASHED_FIELDS_V2 = ['runId', ...HASHED_FIELDS];
const COMMITTED_FIELDS = ['input', 'output', 'dataPayload'];
const REDACTED_MARKER = '[traceglass:redacted]';

/** SPEC §15.1 — the v2 preimage separator, U+0000. */
const NUL = String.fromCharCode(0);

const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

/** The version a record declares; absent means the implicit original (SPEC §15). */
const versionOf = (run) => run.hashVersion ?? 1;

function canonicalStep(step, version = 1) {
  const picked = {};
  for (const f of version === 2 ? HASHED_FIELDS_V2 : HASHED_FIELDS) {
    if (step[f] !== undefined) picked[f] = step[f];
  }
  if (step.commitments) {
    for (const field of COMMITTED_FIELDS) {
      const view = {};
      for (const [p, c] of Object.entries(step.commitments)) {
        if (p === field || p.startsWith(field + '.') || p.startsWith(field + '[')) view[p] = c;
      }
      if (Object.keys(view).length > 0) picked[field] = view;
    }
  }
  return canonicalize(picked);
}

const hashStep = (step, prevHash, version = 1) =>
  version === 2
    ? sha256(`tgstep/2${NUL}${canonicalStep(step, 2)}${NUL}${prevHash}`)
    : sha256(canonicalStep(step, 1) + prevHash);

/** SPEC §15.4 — the v2 run anchor is a hash over the run header. */
function runHashOf(run, anchor) {
  if (run.steps.length === 0) return '';
  if (versionOf(run) !== 2) return anchor;
  const header = {
    hashVersion: 2,
    id: run.id,
    name: run.name,
    startedAt: run.startedAt,
    endedAt: run.endedAt,
    status: run.status,
    currency: run.currency,
    totals: {
      tokens: run.totals.tokens,
      cost: run.totals.cost,
      durationMs: run.totals.durationMs,
      steps: run.totals.steps,
    },
    stepCount: run.steps.length,
    chainAnchor: anchor,
  };
  return sha256(`tgrun/2${NUL}${canonicalize(header)}`);
}

/** SPEC §15.3 — escape a key segment for a v2 path. */
const escapeSegment = (k) => k.replace(/[\\.[]/g, (c) => '\\' + c);

/** SPEC §8.1 / §15.3 */
function walkLeaves(value, visit, basePath = '', version = 1) {
  if (Array.isArray(value)) {
    if (value.length === 0) return visit(basePath, value);
    value.forEach((item, i) => walkLeaves(item, visit, `${basePath}[${i}]`, version));
    return;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return visit(basePath, value);
    for (const k of keys) {
      const seg = version === 2 ? escapeSegment(k) : k;
      walkLeaves(value[k], visit, basePath === '' ? seg : `${basePath}.${seg}`, version);
    }
    return;
  }
  visit(basePath, value);
}

const commitmentFor = (salt, value) => sha256(salt + canonicalize(value));

/** SPEC §8.1 — v1 path tokenization. */
function tokenizePath(path) {
  const tokens = [];
  for (const part of path.split('.')) {
    const m = part.match(/^([^[\]]*)((\[\d+\])*)$/);
    if (!m) { tokens.push(part); continue; }
    if (m[1]) tokens.push(m[1]);
    for (const idx of m[2]?.match(/\d+/g) ?? []) tokens.push(idx);
  }
  return tokens;
}

/** SPEC §15.3 — v2 path tokenization: escape-aware, keeps empty segments. */
function tokenizePathV2(path) {
  const tokens = [];
  let seg = '';
  let segOpen = true;
  for (let i = 0; i < path.length; i++) {
    const c = path[i];
    if (c === '\\' && i + 1 < path.length) { seg += path[++i]; segOpen = true; continue; }
    if (c === '.') {
      if (segOpen) { tokens.push(seg); seg = ''; }
      segOpen = true;
      continue;
    }
    if (c === '[') {
      const close = path.indexOf(']', i);
      const digits = close === -1 ? null : path.slice(i + 1, close);
      if (digits !== null && /^\d+$/.test(digits)) {
        if (segOpen) { tokens.push(seg); seg = ''; }
        tokens.push(digits);
        segOpen = false;
        i = close;
        continue;
      }
    }
    seg += c;
    segOpen = true;
  }
  if (segOpen) tokens.push(seg);
  return tokens;
}

/** Split a commitment path into its payload field and the tokens inside it. */
function splitCommitmentPath(path, version) {
  if (version === 2) {
    const t = tokenizePathV2(path);
    return { field: t[0] ?? '', tokens: t.slice(1) };
  }
  const field = path.split(/[.[]/)[0];
  const rest = path.slice(field.length).replace(/^\./, '');
  return { field, tokens: rest === '' ? [] : tokenizePath(rest) };
}

function getAtTokens(root, tokens) {
  let cur = root;
  for (const tok of tokens) {
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = cur[tok];
  }
  return cur;
}

function getAtPath(root, path) {
  if (path === '') return root;
  return getAtTokens(root, tokenizePath(path));
}

/** SPEC §15.5 — the digest a redaction seal signs. */
function redactionsHashOf(run) {
  const log = run.steps
    .filter((s) => s.redactions && s.redactions.length > 0)
    .map((s) => ({ stepId: s.id, redactions: s.redactions }));
  return sha256(`tgredact/2${NUL}${canonicalize(log)}`);
}

/* ================================================================== *
 * Verification (SPEC §9)                                              *
 * ================================================================== */

function verifyRun(run) {
  const problems = [];
  const version = versionOf(run);
  if (version !== 1 && version !== 2) return [`unsupported hashVersion ${version}`];

  let prev = '';
  for (const step of run.steps) {
    const expected = hashStep(step, prev, version);
    if (step.prevHash !== prev) problems.push(`step ${step.id}: prevHash linkage broken`);
    else if (step.hash !== expected) problems.push(`step ${step.id}: hash mismatch`);
    if (problems.length) break;
    prev = step.hash;
  }
  if (!problems.length && run.runHash !== runHashOf(run, prev)) {
    problems.push(version === 2 ? 'runHash != run header hash' : 'runHash != final step hash');
  }

  if (!problems.length) {
    for (const step of run.steps) {
      if (!step.commitments) continue;
      const salts = step.salts ?? {};
      const declared = new Set((step.redactions ?? []).map((r) => r.path));
      for (const [path, commitment] of Object.entries(step.commitments)) {
        const salt = salts[path];
        const { field, tokens } = splitCommitmentPath(path, version);
        const value = getAtTokens(step[field], tokens);
        if (salt === undefined) {
          // v1: a missing salt is accepted as a redaction, no questions asked.
          // v2 (SPEC §15.6): the record must ADMIT the erasure — marker in place
          // AND a matching entry in the step's redaction log.
          if (version === 2 && !(declared.has(path) && value === REDACTED_MARKER)) {
            problems.push(`step ${step.id}: undeclared erasure at ${path}`);
          }
          continue;
        }
        if (commitmentFor(salt, value) !== commitment) {
          problems.push(`step ${step.id}: commitment mismatch at ${path}`);
        }
      }
    }
  }

  if (!problems.length && run.signature) {
    const sig = run.signature;
    const payload = canonicalize({ runId: run.id, runHash: run.runHash, signedAt: sig.signedAt });
    const ok = edVerify(null, Buffer.from(payload, 'utf8'), createPublicKey(sig.publicKey), Buffer.from(sig.signature, 'base64'));
    if (!ok) problems.push('signature invalid');
    const der = createPublicKey(sig.publicKey).export({ type: 'spki', format: 'der' });
    const kid = createHash('sha256').update(der).digest('hex').slice(0, 16);
    if (kid !== sig.keyId) problems.push(`keyId ${sig.keyId} does not derive from the embedded public key (expected ${kid})`);
  }

  // SPEC §15.5 — the redaction seal, when one is present.
  if (!problems.length && run.redactionSeal) {
    const seal = run.redactionSeal;
    const expected = redactionsHashOf(run);
    if (seal.redactionsHash !== expected) problems.push('redaction seal: digest does not match the log');
    else {
      const payload = canonicalize({
        runId: run.id,
        runHash: run.runHash,
        redactionsHash: expected,
        sealedAt: seal.sealedAt,
      });
      const ok = edVerify(null, Buffer.from(payload, 'utf8'), createPublicKey(seal.publicKey), Buffer.from(seal.signature, 'base64'));
      if (!ok) problems.push('redaction seal invalid');
    }
  }
  return problems;
}

/* ================================================================== *
 * Run the corpus                                                      *
 * ================================================================== */

let pass = 0;
const fail = [];
const check = (name, actual, expected) => {
  if (actual === expected) pass++;
  else fail.push(`${name}\n    expected ${JSON.stringify(expected)}\n    actual   ${JSON.stringify(actual)}`);
};

for (const v of load('01-canonical.json').vectors) {
  const c = canonicalize(JSON.parse(v.inputJson));
  check(`01 canonical/${v.name}`, c, v.canonical);
  check(`01 sha256/${v.name}`, sha256(c), v.sha256);
}

const two = load('02-commitments.json');
for (const v of two.walk) {
  const leaves = [];
  walkLeaves(JSON.parse(v.inputJson), (p, l) => leaves.push({ path: p, canonicalLeaf: canonicalize(l) }), v.field);
  check(`02 walk/${v.name}`, JSON.stringify(leaves), JSON.stringify(v.leaves));
}
for (const v of two.commitments) {
  check(`02 commit/${v.name}`, commitmentFor(v.salt, JSON.parse(v.valueJson)), v.commitment);
}

const three = load('03-steps.json');
const runFile = (n) => load(`04-runs/${n}.tgev.json`).run;
for (const [name, expectations] of Object.entries(three.runs)) {
  const run = runFile(name);
  expectations.forEach((exp, i) => {
    const step = run.steps[i];
    check(`03 canonicalStep/${name}#${i}`, canonicalStep(step), exp.canonicalStep);
    check(`03 hash/${name}#${i}`, hashStep(step, exp.prevHash), exp.hash);
  });
}

const five = load('05-signature.json');
check('05 signaturePayload',
  canonicalize({ runId: five.runId, runHash: five.runHash, signedAt: five.signedAt }),
  five.signaturePayload);
check('05 keyId',
  createHash('sha256').update(createPublicKey(five.publicKeyPem).export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 16),
  five.keyId);

for (const name of ['minimal', 'committed', 'redacted', 'signed']) {
  check(`09 verify/${name}`, verifyRun(runFile(name)).join('; '), '');
}

// The defining property of commitment-based redaction.
check('08 redaction preserves the anchor', runFile('redacted').runHash, runFile('committed').runHash);

/* ================================================================== *
 * tgcanon/2 (SPEC §15)                                                *
 * ================================================================== */

const v2 = load('06-v2.json');

for (const v of v2.walk) {
  const leaves = [];
  walkLeaves(JSON.parse(v.inputJson), (p, l) => leaves.push({ path: p, canonicalLeaf: canonicalize(l) }), v.field, 2);
  check(`06 walk-v2/${v.name}`, JSON.stringify(leaves), JSON.stringify(v.leaves));
}

for (const [name, expectations] of Object.entries(v2.runs)) {
  const run = runFile(name);
  check(`06 declares hashVersion 2/${name}`, run.hashVersion, 2);
  expectations.forEach((exp, i) => {
    const step = run.steps[i];
    check(`06 canonicalStep-v2/${name}#${i}`, canonicalStep(step, 2), exp.canonicalStep);
    check(
      `06 preimage-v2/${name}#${i}`,
      JSON.stringify(`tgstep/2${NUL}${canonicalStep(step, 2)}${NUL}${exp.prevHash}`),
      exp.hashPreimageEscaped,
    );
    check(`06 hash-v2/${name}#${i}`, hashStep(step, exp.prevHash, 2), exp.hash);
  });
}

// The run header — the thing that puts currency/status/totals inside the anchor.
check('06 runHash-v2', sha256(`tgrun/2${NUL}${canonicalize(v2.runHash.header)}`), v2.runHash.runHash);
check('06 runHash-v2 matches the record', runFile('v2-signed').runHash, v2.runHash.runHash);

check(
  '06 signaturePayload-v2',
  canonicalize({ runId: 'vec-v2', runHash: v2.runHash.runHash, signedAt: v2.signature.signedAt }),
  v2.signature.signaturePayload,
);

// The redaction seal.
const sealedRun = runFile('v2-redacted-sealed');
check('06 redactionsHash', redactionsHashOf(sealedRun), v2.redactionSeal.redactionsHash);
check(
  '06 redactionSeal payload',
  canonicalize({
    runId: sealedRun.id,
    runHash: sealedRun.runHash,
    redactionsHash: v2.redactionSeal.redactionsHash,
    sealedAt: v2.redactionSeal.sealedAt,
  }),
  v2.redactionSeal.sealPayload,
);

for (const name of ['v2-signed', 'v2-redacted-sealed']) {
  check(`06 verify/${name}`, verifyRun(runFile(name)).join('; '), '');
}

// v2's headline property: the anchor still survives a redaction.
check('06 redaction preserves the anchor', sealedRun.runHash, runFile('v2-signed').runHash);

// ...and the redacted leaf is the dotted key that v1 could not even address.
check(
  '06 the redacted path is escaped',
  Object.keys(runFile('v2-signed').steps[0].commitments).includes(v2.redactionSeal.redactedPath),
  true,
);

// v2 refuses an erasure the record does not admit to (SPEC §15.6).
{
  const tampered = structuredClone(sealedRun);
  tampered.steps[0].redactions = [];
  check(
    '06 undeclared erasure is rejected',
    verifyRun(tampered).some((p) => p.includes('undeclared erasure')),
    true,
  );
}

/* ================================================================== *
 * The compatibility invariant                                         *
 * ================================================================== */

// Two records produced by the LAST build before tgcanon/2 existed, committed
// unmodified. They declare no hashVersion, so a conforming verifier must read
// them as version 1 and they must still verify — that is the whole promise.
for (const name of ['legacy-signed', 'legacy-redacted']) {
  const run = runFile(name);
  check(`10 legacy/${name} declares no version`, run.hashVersion, undefined);
  check(`10 legacy/${name} verifies`, verifyRun(run).join('; '), '');
  check(`10 legacy/${name} anchors on the final step hash`, run.runHash, run.steps[run.steps.length - 1].hash);
}
check(
  '10 legacy redaction preserved the anchor',
  runFile('legacy-redacted').runHash,
  runFile('legacy-signed').runHash,
);

console.log(`${pass} checks passed, ${fail.length} failed`);
if (fail.length) {
  for (const f of fail) console.error('  FAIL ' + f);
  process.exit(1);
}
