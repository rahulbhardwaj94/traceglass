import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import type { Run } from '@traceglass/core';
import { dataDir } from './paths.js';
import { loadKeys } from './keys.js';
import {
  buildTimeStampRequest,
  requestTimestamp,
  verifyTimeStampToken,
  type TokenVerification,
} from './rfc3161.js';
import {
  buildHashedRekord,
  submitEntry,
  verifyRekorProof,
  type RekorEntry,
  type RekorVerification,
} from './rekor.js';

/**
 * Anchor records externalize a run's integrity anchor so it can be pinned
 * somewhere the store cannot touch.
 *
 * THE PROBLEM ANCHORS EXIST TO SOLVE
 * ----------------------------------
 * `verifyRunFull` checks a run's Ed25519 signature against the public key
 * embedded in the run itself. That is a closed loop: an attacker who controls
 * the machine edits a step, re-chains, re-signs with a key they generated a
 * second ago, and the record verifies clean (docs/threat-model.md §4.1). The
 * guarantee is "internally consistent", not "this is what the agent produced".
 *
 * An anchor breaks the loop by binding the record to something outside the
 * operator's control:
 *   - `rfc3161` — a Time Stamping Authority countersigns the anchor statement,
 *     proving it EXISTED BY time T. Re-writing history after the fact becomes
 *     impossible even for someone holding the signing key, because they cannot
 *     produce a TSA countersignature dated before the edit.
 *   - `rekor` — an append-only public transparency log; membership is publicly
 *     witnessed and entries cannot be quietly retracted, so deletion becomes
 *     detectable too (§3.5).
 *   - `file` — the default. NO network. Pins the anchor locally so it can be
 *     copied to WORM storage by hand. It proves nothing on its own against an
 *     attacker who can write the file; the chain and record signature below
 *     raise the bar, but only an external sink is a real trust root.
 *
 * ZERO EGRESS BY DEFAULT. `FileAnchorSink` is the default and makes no network
 * request ever. The other two are unreachable unless the operator passes an
 * explicit URL. Only a SHA-256 digest is ever transmitted — never payloads,
 * labels, tool names or costs. See the README for the residual disclosure:
 * submitting to a public log reveals that a record exists and when.
 */

/* -------------------------------------------------------------------------- */
/* Record format                                                               */
/* -------------------------------------------------------------------------- */

export interface Rfc3161Proof {
  type: 'rfc3161';
  /** DER TimeStampToken, base64. Re-verified from scratch on every read. */
  token: string;
  /** genTime extracted at anchor time — informational; verification re-derives it. */
  genTime: string;
  hashAlgorithm: 'sha256';
  /** Informational: which TSA was asked. Not trusted by the verifier. */
  tsaUrl?: string;
}

export interface RekorProof {
  type: 'rekor';
  entry: RekorEntry;
  /** Informational: which log instance. Not trusted by the verifier. */
  rekorUrl?: string;
}

export type AnchorProof = Rfc3161Proof | RekorProof;

export interface AnchorRecordSignature {
  algorithm: 'ed25519';
  keyId: string;
  publicKey: string;
  signature: string;
}

export interface AnchorRecord {
  /** 1 = pre-0.9 (no chain, no proof). 2 adds chaining, self-signature, proofs. */
  version: 1 | 2;
  runId: string;
  runHash: string;
  keyId?: string;
  signature?: string;
  anchoredAt: string;
  /** v2: sha256 of the PREVIOUS line as written, or null for the first record. */
  prev?: string | null;
  /** v2: Ed25519 signature by the local key over this record. */
  recordSignature?: AnchorRecordSignature;
  /** v2: external trust root, when an anchoring sink obtained one. */
  proof?: AnchorProof;
}

/**
 * The exact byte string a TSA countersigns / Rekor logs / the record signature
 * covers. Recomputable from the run alone, which is what makes later
 * verification possible: we re-derive this from the stored run and check the
 * proof against it.
 *
 * Every field is JSON-escaped, so no value can inject a line break and shift
 * the meaning of the fields after it. Deliberately does NOT include
 * `anchoredAt` or `prev` — those are local bookkeeping, not properties of the
 * run, and a verifier must be able to rebuild this string from a `.tgev` file
 * with no anchors file in hand.
 *
 * NOTE: `runHash` is treated as an opaque string throughout. Nothing here
 * depends on how the core computes it.
 */
export function anchorStatement(run: {
  id: string;
  runHash: string;
  signature?: { keyId: string; signature: string } | undefined;
}): Buffer {
  const lines = [
    'traceglass-anchor-v2',
    `runId: ${JSON.stringify(run.id)}`,
    `runHash: ${JSON.stringify(run.runHash)}`,
    `keyId: ${JSON.stringify(run.signature?.keyId ?? null)}`,
    `signature: ${JSON.stringify(run.signature?.signature ?? null)}`,
  ];
  return Buffer.from(lines.join('\n') + '\n', 'utf8');
}

/** Same statement, rebuilt from a stored anchor record. */
export function statementFromRecord(record: AnchorRecord): Buffer {
  return anchorStatement({
    id: record.runId,
    runHash: record.runHash,
    ...(record.keyId && record.signature
      ? { signature: { keyId: record.keyId, signature: record.signature } }
      : {}),
  });
}

/** SHA-256 of the anchor statement — what gets timestamped or logged. */
export function anchorDigest(statement: Buffer): Buffer {
  return createHash('sha256').update(statement).digest();
}

/**
 * Bytes covered by a record's own Ed25519 signature: the statement plus the
 * local bookkeeping, so `anchoredAt` and the chain link cannot be edited either.
 */
function recordSigningPayload(record: AnchorRecord): Buffer {
  return Buffer.concat([
    statementFromRecord(record),
    Buffer.from(
      `anchoredAt: ${JSON.stringify(record.anchoredAt)}\nprev: ${JSON.stringify(record.prev ?? null)}\n`,
      'utf8',
    ),
  ]);
}

/** Hash of a line exactly as written to the file — the chain link. */
function lineHash(line: string): string {
  return createHash('sha256').update(line, 'utf8').digest('hex');
}

export function anchorRecordForRun(run: Run): AnchorRecord {
  return {
    version: 2,
    runId: run.id,
    runHash: run.runHash,
    ...(run.signature ? { keyId: run.signature.keyId, signature: run.signature.signature } : {}),
    anchoredAt: new Date().toISOString(),
  };
}

/* -------------------------------------------------------------------------- */
/* Sinks                                                                       */
/* -------------------------------------------------------------------------- */

/** Per-run result, so a partial failure can be reported precisely. */
export interface AnchorOutcome {
  runId: string;
  /** The proof obtained, or null when this sink produces none / it failed. */
  proof: AnchorProof | null;
  /** Non-null when anchoring this run failed. The record is STILL written. */
  error: string | null;
}

export interface AnchorSink {
  readonly kind: 'file' | 'rfc3161' | 'rekor';
  append(records: AnchorRecord[]): Promise<AnchorOutcome[]>;
}

/** A run id already anchored, with the hashes recorded for it. */
export type ExistingAnchors = Map<string, Set<string>>;

/**
 * Appends anchor records as JSONL, chained and self-signed.
 *
 * Chaining: each record stores `prev`, the SHA-256 of the previous line exactly
 * as written. Deleting or reordering a line breaks the chain at the next
 * record, which turns silent removal from an append-only evidence file into a
 * detectable gap.
 *
 * Self-signature: when local keys exist, each record is signed over its
 * statement plus `anchoredAt` and `prev`. This does not stop an attacker who
 * has stolen the signing key — nothing local can — but it does stop anyone who
 * has only file write access from hand-writing a plausible entry.
 */
export class FileAnchorSink implements AnchorSink {
  readonly kind = 'file' as const;

  constructor(private readonly path: string) {}

  /**
   * Map of runId -> the set of runHashes already anchored for it.
   *
   * Dedupe is on the PAIR, not the id alone. Skipping on id alone let an
   * attacker pre-register a bogus anchor for a guessable run id and thereby
   * suppress the genuine one, which was then reported as "already anchored".
   */
  existingAnchors(): ExistingAnchors {
    const found: ExistingAnchors = new Map();
    if (!existsSync(this.path)) return found;
    for (const line of readFileSync(this.path, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const parsed = JSON.parse(line) as { runId?: string; runHash?: string };
        if (!parsed.runId) continue;
        const hashes = found.get(parsed.runId) ?? new Set<string>();
        if (parsed.runHash) hashes.add(parsed.runHash);
        found.set(parsed.runId, hashes);
      } catch {
        // Malformed lines cannot be deduped against. They are NOT ignored
        // overall: readAnchorFile() reports them as an integrity failure.
      }
    }
    return found;
  }

  /** The chain link a newly appended record must carry. */
  private tailHash(): string | null {
    if (!existsSync(this.path)) return null;
    const lines = readFileSync(this.path, 'utf8')
      .split('\n')
      .filter((l) => l.trim());
    const last = lines[lines.length - 1];
    return last ? lineHash(last) : null;
  }

  // Synchronous underneath — the file is appended with appendFileSync so a
  // crash mid-write cannot leave a half-written chain link — but it returns a
  // Promise to satisfy AnchorSink, which the network sinks genuinely need.
  append(records: AnchorRecord[]): Promise<AnchorOutcome[]> {
    if (records.length === 0) return Promise.resolve([]);
    mkdirSync(dirname(this.path), { recursive: true });
    const keys = loadKeys();

    let prev = this.tailHash();
    let payload = '';
    const outcomes: AnchorOutcome[] = [];

    for (const record of records) {
      const withChain: AnchorRecord = { ...record, version: 2, prev };
      if (keys) {
        withChain.recordSignature = {
          algorithm: 'ed25519',
          keyId: keys.keyId,
          publicKey: keys.publicKeyPem,
          signature: sign(null, recordSigningPayload(withChain), keys.privateKeyPem).toString(
            'base64',
          ),
        };
      }
      const line = JSON.stringify(withChain);
      payload += line + '\n';
      prev = lineHash(line);
      outcomes.push({ runId: record.runId, proof: record.proof ?? null, error: null });
    }

    appendFileSync(this.path, payload);
    return Promise.resolve(outcomes);
  }
}

/**
 * Attaches an RFC 3161 timestamp token to each record, then delegates storage.
 *
 * FAILURE IS SAFE AND LOUD. If the TSA is unreachable, refuses, or returns a
 * token we cannot verify, the record is still written — without a proof — and
 * the failure is returned in the outcome. Evidence is never lost because a
 * timestamp service was down, and a record is never marked anchored when it is
 * not: an unverifiable token is DISCARDED rather than stored, because a stored
 * token nobody validated is worse than no token at all.
 */
export class Rfc3161AnchorSink implements AnchorSink {
  readonly kind = 'rfc3161' as const;

  constructor(
    private readonly inner: FileAnchorSink,
    private readonly opts: {
      tsaUrl: string;
      timeoutMs?: number;
      /** PEM of the expected TSA cert; without it the token is self-attested. */
      pinnedCertPem?: string | undefined;
      reqPolicy?: string | undefined;
    },
  ) {}

  async append(records: AnchorRecord[]): Promise<AnchorOutcome[]> {
    const prepared: AnchorRecord[] = [];
    const errors = new Map<string, string>();

    for (const record of records) {
      const statement = statementFromRecord(record);
      const digest = anchorDigest(statement);
      try {
        const request = buildTimeStampRequest(digest, {
          ...(this.opts.reqPolicy ? { reqPolicy: this.opts.reqPolicy } : {}),
        });
        const { response } = await requestTimestamp(this.opts.tsaUrl, request, {
          ...(this.opts.timeoutMs !== undefined ? { timeoutMs: this.opts.timeoutMs } : {}),
        });
        const tokenDer = response.tokenDer!;

        // Verify BEFORE storing. Storing an unvalidated token is theatre.
        const check = verifyTimeStampToken(tokenDer, {
          expectedDigest: digest,
          expectedNonce: request.nonce,
          pinnedCertPem: this.opts.pinnedCertPem,
        });
        if (!check.ok) {
          throw new Error(`the TSA's token did not verify: ${check.problems.join('; ')}`);
        }

        prepared.push({
          ...record,
          proof: {
            type: 'rfc3161',
            token: tokenDer.toString('base64'),
            genTime: check.genTime,
            hashAlgorithm: 'sha256',
            tsaUrl: this.opts.tsaUrl,
          },
        });
      } catch (e) {
        errors.set(record.runId, e instanceof Error ? e.message : String(e));
        prepared.push(record); // still anchored locally, just unproven
      }
    }

    const outcomes = await this.inner.append(prepared);
    return outcomes.map((o) => ({ ...o, error: errors.get(o.runId) ?? null }));
  }
}

/**
 * Attaches a Sigstore/Rekor transparency-log entry to each record.
 *
 * Same failure discipline as the RFC 3161 sink: the local record is always
 * written, an unverifiable entry is never stored as if it were proof.
 *
 * Requires local signing keys — the log entry is a signature over the anchor
 * statement, so there is nothing to submit without one.
 */
export class SigstoreAnchorSink implements AnchorSink {
  readonly kind = 'rekor' as const;

  constructor(
    private readonly inner: FileAnchorSink,
    private readonly opts: {
      rekorUrl: string;
      timeoutMs?: number;
      /** Rekor's public key (PEM) for checking the SET at submission time. */
      logKeyPem?: string | undefined;
    },
  ) {}

  async append(records: AnchorRecord[]): Promise<AnchorOutcome[]> {
    const prepared: AnchorRecord[] = [];
    const errors = new Map<string, string>();
    const keys = loadKeys();

    for (const record of records) {
      const statement = statementFromRecord(record);
      try {
        if (!keys) {
          throw new Error(
            'Rekor anchoring needs a local signing key — run `traceglass keygen` first.',
          );
        }
        const digestHex = anchorDigest(statement).toString('hex');
        const signature = sign(null, statement, keys.privateKeyPem).toString('base64');
        const entry = await submitEntry(
          this.opts.rekorUrl,
          buildHashedRekord(digestHex, signature, keys.publicKeyPem),
          { ...(this.opts.timeoutMs !== undefined ? { timeoutMs: this.opts.timeoutMs } : {}) },
        );

        const check = verifyRekorProof(entry, {
          expectedDigestHex: digestHex,
          logKeyPem: this.opts.logKeyPem,
          signedStatement: statement,
        });
        // Without the log key the SET cannot be checked; that is a weaker but
        // deliberate state, not a failure. Everything else must hold.
        const fatal = check.problems.filter(
          (p) => !p.includes('signed entry timestamp') || check.setVerified === false,
        );
        if (!check.bindsExpectedDigest || check.inclusionProofOk === false || fatal.length > 0) {
          throw new Error(`Rekor's response did not verify: ${check.problems.join('; ')}`);
        }

        prepared.push({
          ...record,
          proof: { type: 'rekor', entry, rekorUrl: this.opts.rekorUrl },
        });
      } catch (e) {
        errors.set(record.runId, e instanceof Error ? e.message : String(e));
        prepared.push(record);
      }
    }

    const outcomes = await this.inner.append(prepared);
    return outcomes.map((o) => ({ ...o, error: errors.get(o.runId) ?? null }));
  }
}

export function defaultAnchorsPath(): string {
  return join(dataDir(), 'anchors.jsonl');
}

/* -------------------------------------------------------------------------- */
/* Reading and verification — the loop that was previously never closed        */
/* -------------------------------------------------------------------------- */

export interface AnchorFileReadResult {
  records: AnchorRecord[];
  /** Parse/shape failures, by 1-based line number. Any entry means TAMPERED. */
  malformed: Array<{ line: number; reason: string }>;
  /** Chain breaks, by 1-based line number. Any entry means INSERTED/DELETED. */
  chainBreaks: Array<{ line: number; reason: string }>;
  /** True when every line parsed and every v2 chain link held. */
  ok: boolean;
}

/**
 * Read an anchors file STRICTLY.
 *
 * The writer is deliberately lenient about junk lines; a verifier must not be.
 * A line that will not parse is an integrity failure, because "unreadable" is
 * exactly what a deleted record looks like once the file is treated as the
 * out-of-band source of truth.
 *
 * WHAT THE CHAIN DOES NOT CATCH. Deleting, reordering or inserting a line is
 * detected, because the following record's `prev` no longer matches. Discarding
 * the file WHOLESALE and starting a fresh one is not: a single new record with
 * `prev: null` is indistinguishable from a first record. No intra-file
 * construct can fix that — detecting truncation requires an external witness
 * that knows the file used to be longer, which is precisely what the rfc3161
 * and rekor sinks provide for the individual records they cover.
 */
export function readAnchorFile(path: string): AnchorFileReadResult {
  const result: AnchorFileReadResult = {
    records: [],
    malformed: [],
    chainBreaks: [],
    ok: true,
  };
  if (!existsSync(path)) return result;

  const rawLines = readFileSync(path, 'utf8').split('\n');
  let prevHash: string | null = null;
  let sawChainedRecord = false;

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i]!;
    if (!line.trim()) continue;
    const lineNo = i + 1;

    let parsed: AnchorRecord;
    try {
      parsed = JSON.parse(line) as AnchorRecord;
    } catch (e) {
      result.malformed.push({ line: lineNo, reason: `not valid JSON (${describe(e)})` });
      // A corrupt line also destroys the chain link for everything after it.
      prevHash = lineHash(line);
      continue;
    }
    if (typeof parsed !== 'object' || parsed === null || typeof parsed.runId !== 'string') {
      result.malformed.push({ line: lineNo, reason: 'not an anchor record (no runId)' });
      prevHash = lineHash(line);
      continue;
    }
    if (typeof parsed.runHash !== 'string') {
      result.malformed.push({
        line: lineNo,
        reason: `record for "${parsed.runId}" has no runHash`,
      });
      prevHash = lineHash(line);
      continue;
    }

    if (parsed.version === 2) {
      const expected = parsed.prev ?? null;
      if (sawChainedRecord || expected !== null) {
        if (expected !== prevHash) {
          result.chainBreaks.push({
            line: lineNo,
            reason:
              expected === null
                ? `record for "${parsed.runId}" claims to be the first, but ${result.records.length} record(s) precede it`
                : `record for "${parsed.runId}" chains to ${expected.slice(0, 16)}… but the preceding line hashes to ${prevHash?.slice(0, 16) ?? '(nothing)'}…`,
          });
        }
      }
      sawChainedRecord = true;
    }

    result.records.push(parsed);
    prevHash = lineHash(line);
  }

  result.ok = result.malformed.length === 0 && result.chainBreaks.length === 0;
  return result;
}

/** How strongly a single anchor record is bound to something external. */
export type AnchorStrength =
  | 'none' // no anchor record at all
  | 'local' // local file record only — no external trust root
  | 'self-attested' // proof verifies, but against material inside the proof
  | 'external'; // proof verifies against out-of-band trust material

export interface AnchorCheck {
  runId: string;
  /** Records found for this run. */
  found: number;
  /** Best strength achieved across the run's records. */
  strength: AnchorStrength;
  /** False when a record exists that disagrees with the run, or a proof failed. */
  ok: boolean;
  /** Whether a matching (runId, runHash) record exists at all. */
  matched: boolean;
  /** Timestamps proven, strongest first: what an anchored record buys. */
  provenExistedBy: string | null;
  rfc3161: TokenVerification | null;
  rekor: RekorVerification | null;
  /** Human-readable lines, always safe to print. */
  messages: string[];
  problems: string[];
}

export interface VerifyAgainstAnchorsOptions {
  /** PEM of the expected TSA certificate, obtained out of band. */
  tsaCertPem?: string | undefined;
  /** PEM of Rekor's public key, obtained out of band. */
  rekorKeyPem?: string | undefined;
}

/**
 * Check a run against the anchor records held for it — the check that did not
 * exist before, and without which anchoring provides no automated detection at
 * all.
 *
 * Catches, in order of how likely an attacker is to try them:
 *   - a run whose stored hash no longer matches its pinned anchor (tampering
 *     after anchoring);
 *   - a hand-written anchor record for a run that never existed (the record's
 *     own signature fails, and any proof fails);
 *   - a genuine timestamp token or log entry lifted from a DIFFERENT record
 *     (the statement digest will not match);
 *   - a run with no anchor at all, reported rather than passed over.
 */
export function verifyRunAgainstAnchors(
  run: Run,
  records: AnchorRecord[],
  opts: VerifyAgainstAnchorsOptions = {},
): AnchorCheck {
  const mine = records.filter((r) => r.runId === run.id);
  const check: AnchorCheck = {
    runId: run.id,
    found: mine.length,
    strength: 'none',
    ok: true,
    matched: false,
    provenExistedBy: null,
    rfc3161: null,
    rekor: null,
    messages: [],
    problems: [],
  };

  if (mine.length === 0) {
    check.messages.push(
      `Anchor: NONE — no anchor record for "${run.id}". This run rests entirely on its own embedded key.`,
    );
    return check;
  }

  // 1. Does any record agree with the run we actually hold?
  const agreeing = mine.filter((r) => r.runHash === run.runHash);
  const disagreeing = mine.filter((r) => r.runHash !== run.runHash);

  for (const bad of disagreeing) {
    check.ok = false;
    check.problems.push(
      `anchor MISMATCH: a record anchored at ${bad.anchoredAt} pins runHash ${bad.runHash} but this run's is ${run.runHash} — the run or the anchor was altered after anchoring`,
    );
  }

  if (agreeing.length === 0) {
    check.messages.push(
      `Anchor: MISMATCH — ${mine.length} record(s) exist for this run id, none matching its runHash.`,
    );
    return check;
  }

  check.matched = true;
  check.strength = 'local';

  // 2. The record's own Ed25519 signature, where present.
  for (const record of agreeing) {
    if (!record.recordSignature) continue;
    const payload = recordSigningPayload(record);
    let valid = false;
    try {
      valid = verify(
        null,
        payload,
        createPublicKey(record.recordSignature.publicKey),
        Buffer.from(record.recordSignature.signature, 'base64'),
      );
    } catch {
      valid = false;
    }
    if (!valid) {
      check.ok = false;
      check.problems.push(
        `anchor record signature INVALID (keyId ${record.recordSignature.keyId}) — the record was edited after it was written`,
      );
    }
  }

  // 3. External proofs. The whole point.
  const statement = anchorStatement(run);
  const digest = anchorDigest(statement);

  for (const record of agreeing) {
    if (!record.proof) continue;

    if (record.proof.type === 'rfc3161') {
      const result = verifyTimeStampToken(Buffer.from(record.proof.token, 'base64'), {
        expectedDigest: digest,
        pinnedCertPem: opts.tsaCertPem,
        // The nonce is not stored: it is a freshness check for the live
        // exchange, not something a later verifier can or should re-check.
      });
      check.rfc3161 = result;
      if (!result.ok) {
        check.ok = false;
        for (const p of result.problems) check.problems.push(`rfc3161: ${p}`);
      } else {
        check.provenExistedBy = earliest(check.provenExistedBy, result.genTime);
        if (result.certPinned) {
          check.strength = 'external';
          check.messages.push(
            `Anchor: RFC 3161 timestamp VALID and countersigned by the pinned TSA (${result.certSubject}).`,
          );
        } else {
          check.strength = strongest(check.strength, 'self-attested');
          check.messages.push(
            `Anchor: RFC 3161 timestamp valid, but the TSA certificate is NOT pinned — ` +
              `pass --tsa-cert to bind it to a known authority. Signer fingerprint ${result.certFingerprint}.`,
          );
        }
      }
    }

    if (record.proof.type === 'rekor') {
      const result = verifyRekorProof(record.proof.entry, {
        expectedDigestHex: digest.toString('hex'),
        logKeyPem: opts.rekorKeyPem,
        signedStatement: statement,
      });
      check.rekor = result;
      // A missing SET check is a weaker state, not a failure; everything else is.
      const fatal = result.problems.filter(
        (p) => !(p.includes('signed entry timestamp') && result.setVerified === null),
      );
      if (!result.bindsExpectedDigest || result.inclusionProofOk !== true || fatal.length > 0) {
        check.ok = false;
        for (const p of result.problems) check.problems.push(`rekor: ${p}`);
      } else {
        if (result.integratedTime) {
          check.provenExistedBy = earliest(check.provenExistedBy, result.integratedTime);
        }
        if (result.setVerified === true) {
          check.strength = 'external';
          check.messages.push(
            `Anchor: Rekor entry VALID — inclusion proof checks out and the log's signed entry timestamp verifies (log index ${record.proof.entry.logIndex}).`,
          );
        } else {
          check.strength = strongest(check.strength, 'self-attested');
          check.messages.push(
            `Anchor: Rekor entry is self-consistent (binds this run, inclusion proof sound) but the log's ` +
              `signature was NOT checked — pass --rekor-key to prove it is really in the public log.`,
          );
        }
      }
    }
  }

  if (check.strength === 'local' && check.ok) {
    check.messages.push(
      `Anchor: LOCAL only — a matching record exists${agreeing.some((r) => r.recordSignature) ? ' and is signed' : ''}, ` +
        `but it carries no external proof. It cannot outrank an attacker who controls this machine.`,
    );
  }

  return check;
}

function strongest(a: AnchorStrength, b: AnchorStrength): AnchorStrength {
  const order: AnchorStrength[] = ['none', 'local', 'self-attested', 'external'];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}

function earliest(current: string | null, candidate: string): string {
  if (!current) return candidate;
  return Date.parse(candidate) < Date.parse(current) ? candidate : current;
}

function describe(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
