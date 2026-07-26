import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RunStore, ingestAndFinalize, verifyRunFull, type Run } from '@traceglass/core';
import { startRecording } from '@traceglass/sdk';
import {
  FileAnchorSink,
  anchorDigest,
  anchorRecordForRun,
  anchorStatement,
  readAnchorFile,
  verifyRunAgainstAnchors,
  type AnchorRecord,
} from './anchors.js';
import { generateKeys, maybeSign } from './keys.js';
import { parseTimeStampResponse } from './rfc3161.js';

/**
 * ADVERSARIAL SUITE — anchor forgery (attack 3).
 *
 * These tests were written against 0.8, where they documented five open holes:
 * anchors.jsonl was WRITE-ONLY. Nothing ever read a record back to compare it
 * against a run, so a forged entry was not merely undetected — there was no
 * detector, and `traceglass anchor --all` could be made to silently skip the
 * genuine anchor.
 *
 * They are now regression tests. Each one still performs the original attack;
 * what changed is that the attack is caught, and the assertions pin exactly
 * WHICH mechanism catches it. If any of these starts passing the attacker's
 * way again, the anchoring feature has gone back to being decorative.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-fixtures');

let home: string;
let savedHome: string | undefined;
let anchorsFile: string;
let store: RunStore;
let genuine: Run;

beforeAll(async () => {
  home = mkdtempSync(join(tmpdir(), 'tg-anchor-attack-'));
  savedHome = process.env.TRACEGLASS_HOME;
  process.env.TRACEGLASS_HOME = home;
  anchorsFile = join(home, 'anchors.jsonl');

  generateKeys();
  const rec = startRecording({ name: 'anchored agent', dir: home, id: 'anchored-run' });
  rec.step({ type: 'user_input', label: 'start', input: { account: '4471' } });
  rec.step({ type: 'tool_call', toolName: 'payments.refund', label: 'refund', cost: 1 });
  genuine = await rec.end();

  // The recorder already persisted the run into TRACEGLASS_HOME's store.
  store = new RunStore(join(home, 'traceglass.sqlite'));
});

afterAll(() => {
  store.close();
  if (savedHome === undefined) delete process.env.TRACEGLASS_HOME;
  else process.env.TRACEGLASS_HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
});

function readAnchors(): AnchorRecord[] {
  return readFileSync(anchorsFile, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as AnchorRecord);
}

describe('ATTACK 3: anchor forgery', () => {
  it('a genuine anchor records the run’s real hash and signature', async () => {
    const sink = new FileAnchorSink(anchorsFile);
    await sink.append([anchorRecordForRun(genuine)]);
    const [record] = readAnchors();
    expect(record!.runId).toBe('anchored-run');
    expect(record!.runHash).toBe(genuine.runHash);
    expect(record!.keyId).toBe(genuine.signature!.keyId);
    expect(record!.signature).toBe(genuine.signature!.signature);
  });

  it('FIXED: a hand-written anchor for a run that never existed is now detected', async () => {
    /*
     * WAS: anchors.jsonl carried no signature over its own contents, no
     * sequence number and no chaining, so an attacker with write access could
     * fabricate an entry for a run that was never recorded and then point at
     * "the anchor we pinned in S3" as independent corroboration.
     *
     * NOW: records chain to the SHA-256 of the preceding line and carry an
     * Ed25519 signature over their own contents. Appending a line by hand
     * breaks the chain, and the attacker cannot produce a record signature
     * without the private key.
     */
    const forged: AnchorRecord = {
      version: 2,
      runId: 'run-that-never-happened',
      runHash: 'f'.repeat(64),
      keyId: '0123456789abcdef',
      signature: Buffer.from('not a real signature').toString('base64'),
      anchoredAt: '2026-01-01T00:00:00.000Z',
    };
    appendFileSync(anchorsFile, JSON.stringify(forged) + '\n');

    const file = readAnchorFile(anchorsFile);
    expect(file.ok).toBe(false); // <-- THE HOLE IS CLOSED
    expect(file.chainBreaks).toHaveLength(1);
    expect(file.chainBreaks[0]!.reason).toMatch(/claims to be the first/);

    // The run it claims to anchor still does not exist...
    expect(store.getRun('run-that-never-happened')).toBeNull();
    // ...and it carries no record signature, because forging one needs the key.
    const forgedRecord = file.records.find((r) => r.runId === 'run-that-never-happened');
    expect(forgedRecord?.recordSignature).toBeUndefined();

    // Clean up so later cases start from a coherent file.
    writeFileSync(
      anchorsFile,
      readFileSync(anchorsFile, 'utf8')
        .split('\n')
        .filter((l) => l.trim() && !l.includes('run-that-never-happened'))
        .join('\n') + '\n',
    );
  });

  it('FIXED: `verify` now checks a run against its anchor and catches tampering', () => {
    /*
     * WAS: `FileAnchorSink` had only append() and existingRunIds(). No CLI
     * command read anchors back, so if a run's hash was silently changed in
     * the store the pinned anchor would disagree and nobody would ever find
     * out — detecting the very tampering anchors exist to catch required an
     * operator to diff two files by hand.
     *
     * NOW: verifyRunAgainstAnchors() performs the comparison, and
     * `traceglass verify --anchors` / `traceglass anchor --verify` call it.
     */
    const surface = Object.getOwnPropertyNames(
      Object.getPrototypeOf(new FileAnchorSink(anchorsFile)),
    );
    expect(surface).toContain('existingAnchors');

    const records = readAnchorFile(anchorsFile).records;

    // The genuine run agrees with its anchor.
    const good = verifyRunAgainstAnchors(genuine, records);
    expect(good.matched).toBe(true);
    expect(good.ok).toBe(true);

    // A run whose hash was altered in the store is now caught BY THE ANCHOR,
    // independently of the signature.
    const tamperedRun: Run = { ...genuine, runHash: 'a'.repeat(64) };
    const bad = verifyRunAgainstAnchors(tamperedRun, records);
    expect(bad.ok).toBe(false); // <-- THE HOLE IS CLOSED
    expect(bad.matched).toBe(false);
    expect(bad.problems.join(' ')).toMatch(/anchor MISMATCH/);
    // The signature catches it too; the point is that the anchor no longer
    // stays silent when the signature is the only thing objecting.
    expect(verifyRunFull(tamperedRun).signature.ok).toBe(false);
  });

  it('FIXED: a pre-registered anchor no longer suppresses the genuine one', async () => {
    /*
     * WAS: existingRunIds() deduped purely by runId, so an attacker who guessed
     * a run id could write a bogus anchor for it FIRST; the operator's later
     * `traceglass anchor --all` silently skipped the genuine anchor and
     * reported "(1 already anchored)" as a successful no-op.
     *
     * NOW: dedupe is on the PAIR (runId, runHash). A run id present with a
     * different hash is a CONFLICT: the genuine anchor is written anyway and
     * the CLI reports it loudly and exits non-zero.
     */
    const suppressFile = join(home, 'suppressed.jsonl');
    writeFileSync(
      suppressFile,
      JSON.stringify({
        version: 1,
        runId: 'anchored-run',
        runHash: 'b'.repeat(64), // NOT the genuine anchor
        anchoredAt: '2020-01-01T00:00:00.000Z',
      }) + '\n',
    );

    // This mirrors the dedupe logic in bin.ts `anchor --all`.
    const sink = new FileAnchorSink(suppressFile);
    const existing = sink.existingAnchors();
    const hashes = existing.get(genuine.id);
    const alreadyAnchored = hashes?.has(genuine.runHash) ?? false;
    const conflict = hashes !== undefined && !alreadyAnchored;

    expect(alreadyAnchored).toBe(false);
    expect(conflict).toBe(true); // <-- surfaced, not swallowed

    await sink.append([anchorRecordForRun(genuine)]);
    const records = readFileSync(suppressFile, 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as AnchorRecord);
    expect(records).toHaveLength(2);
    // The genuine anchor SURVIVES alongside the attacker's.
    expect(records.some((r) => r.runHash === genuine.runHash)).toBe(true);

    // And a verifier can tell which one is real: the attacker's record fails.
    const check = verifyRunAgainstAnchors(genuine, records);
    expect(check.matched).toBe(true);
    expect(check.ok).toBe(false);
    expect(check.problems.join(' ')).toMatch(/anchor MISMATCH/);
  });

  it('FIXED: malformed and deleted lines are integrity failures, not silent skips', () => {
    /*
     * WAS: the reader swallowed JSON parse errors, so an attacker could corrupt
     * or delete a specific anchor line and the file still read as valid — the
     * record simply ceased to exist, with nothing to indicate a gap. Deletion
     * from an append-only evidence file was undetectable.
     *
     * NOW: readAnchorFile() treats an unparseable line as an integrity failure
     * AND the chain makes a removal break the following record's link.
     */
    const tamperFile = join(home, 'tampered-anchors.jsonl');
    const chained = new FileAnchorSink(tamperFile);
    return (async () => {
      await chained.append(
        ['run-a', 'run-b', 'run-c'].map((id) => ({
          version: 2 as const,
          runId: id,
          runHash: id.slice(-1).repeat(64),
          anchoredAt: '2026-01-01T00:00:00.000Z',
        })),
      );
      expect(readAnchorFile(tamperFile).ok).toBe(true);
      expect(readAnchorFile(tamperFile).records).toHaveLength(3);

      // Corrupt the middle record.
      const corrupted = readFileSync(tamperFile, 'utf8').replace(
        /^.*run-b.*$/m,
        '{"runId": broken',
      );
      writeFileSync(tamperFile, corrupted);
      const afterCorruption = readAnchorFile(tamperFile);
      expect(afterCorruption.ok).toBe(false); // <-- THE HOLE IS CLOSED
      expect(afterCorruption.malformed).toHaveLength(1);
      expect(afterCorruption.malformed[0]!.reason).toMatch(/not valid JSON/);

      // Outright deleting the line is likewise visible now: run-c's chain link
      // points at a line that is no longer there.
      writeFileSync(
        tamperFile,
        corrupted
          .split('\n')
          .filter((l) => l.trim() && !l.includes('broken'))
          .join('\n') + '\n',
      );
      const afterDeletion = readAnchorFile(tamperFile);
      expect(afterDeletion.records).toHaveLength(2);
      expect(afterDeletion.ok).toBe(false); // <-- deletion detected
      expect(afterDeletion.chainBreaks[0]!.reason).toMatch(/chains to/);
    })();
  });

  it('FIXED: editing a stored record invalidates its signature', async () => {
    // The subtlest tamper: leave the run alone, adjust when it was anchored so
    // it appears to predate an incident.
    const file = join(home, 'edited.jsonl');
    await new FileAnchorSink(file).append([anchorRecordForRun(genuine)]);
    const record = JSON.parse(readFileSync(file, 'utf8').trim()) as AnchorRecord;
    expect(record.recordSignature).toBeDefined();

    const backdated: AnchorRecord = { ...record, anchoredAt: '2019-01-01T00:00:00.000Z' };
    const check = verifyRunAgainstAnchors(genuine, [backdated]);
    expect(check.ok).toBe(false);
    expect(check.problems.join(' ')).toMatch(/record signature INVALID/);
  });

  it('a record without a runId is ignored, so it cannot poison the dedupe set', () => {
    const f = join(home, 'noid.jsonl');
    writeFileSync(f, JSON.stringify({ version: 1, runHash: 'x'.repeat(64) }) + '\n');
    expect(new FileAnchorSink(f).existingAnchors().size).toBe(0);
    // But a verifier still flags it rather than passing over it.
    expect(readAnchorFile(f).ok).toBe(false);
    expect(readAnchorFile(f).malformed[0]!.reason).toMatch(/no runId/);
  });

  it('anchoring an unsigned run records no signature to borrow', () => {
    const unsigned = ingestAndFinalize({
      id: 'unsigned-run',
      name: 'x',
      currency: 'USD',
      steps: [
        { type: 'user_input', label: 'l', startedAt: '2026-01-01T00:00:00.000Z', durationMs: 1 },
      ],
    });
    const record = anchorRecordForRun(unsigned);
    expect(record.signature).toBeUndefined();
    expect(record.keyId).toBeUndefined();
    expect(record.runHash).toBe(unsigned.runHash);
  });

  it('the anchor carries the run’s OWN hash, not one the caller can inject', () => {
    const record = anchorRecordForRun(maybeSign(genuine));
    expect(record.runHash).toBe(genuine.runHash);
    expect(Object.keys(record).sort()).toEqual([
      'anchoredAt',
      'keyId',
      'runHash',
      'runId',
      'signature',
      'version',
    ]);
  });
});

describe('ATTACK 3b: forging or misappropriating an external proof', () => {
  /**
   * With external sinks the attacker's cheapest move is no longer to fabricate
   * a proof — that needs the TSA's key — but to STEAL a genuine one: attach a
   * real, fully-valid timestamp token that was issued over something else.
   * The binding between the token and this specific run is the only thing
   * standing in the way.
   */

  const foreignToken = parseTimeStampResponse(
    readFileSync(join(FIXTURES, 'response.tsr')),
  ).tokenDer!;
  const anchorToken = parseTimeStampResponse(
    readFileSync(join(FIXTURES, 'anchor-response.tsr')),
  ).tokenDer!;
  const canned = JSON.parse(readFileSync(join(FIXTURES, 'anchor-run.json'), 'utf8')) as {
    runId: string;
    runHash: string;
    keyId: string;
    signature: string;
  };
  const tsaCertPem = readFileSync(join(FIXTURES, 'tsa-cert.pem'), 'utf8');

  /** A Run-shaped object matching the canned fixture statement. */
  const cannedRun = {
    id: canned.runId,
    runHash: canned.runHash,
    signature: { keyId: canned.keyId, signature: canned.signature },
  } as unknown as Run;

  it('the anchor statement format is frozen — the committed fixture still reproduces', () => {
    /*
     * If anchorStatement() ever drifts, every anchor issued before the change
     * silently stops verifying. The fixture bytes were written by the
     * generator script, independently of this implementation.
     */
    const expected = readFileSync(join(FIXTURES, 'anchor-statement.bin'));
    expect(anchorStatement(cannedRun).equals(expected)).toBe(true);
  });

  it('a genuine TSA token over this run’s statement verifies end to end', () => {
    const record: AnchorRecord = {
      version: 2,
      runId: canned.runId,
      runHash: canned.runHash,
      keyId: canned.keyId,
      signature: canned.signature,
      anchoredAt: '2026-07-25T00:00:00.000Z',
      proof: {
        type: 'rfc3161',
        token: anchorToken.toString('base64'),
        genTime: '2026-07-25T00:00:00.000Z',
        hashAlgorithm: 'sha256',
      },
    };
    const check = verifyRunAgainstAnchors(cannedRun, [record], { tsaCertPem });
    expect(check.problems).toEqual([]);
    expect(check.ok).toBe(true);
    expect(check.strength).toBe('external');
    expect(check.rfc3161?.certPinned).toBe(true);
    expect(check.provenExistedBy).not.toBeNull();
  });

  it('THE ATTACK: a genuine token issued over a DIFFERENT document is rejected', () => {
    // `response.tsr` is a real, cryptographically valid TSA token — it simply
    // timestamps something that is not this run's anchor statement.
    const record: AnchorRecord = {
      version: 2,
      runId: canned.runId,
      runHash: canned.runHash,
      keyId: canned.keyId,
      signature: canned.signature,
      anchoredAt: '2026-07-25T00:00:00.000Z',
      proof: {
        type: 'rfc3161',
        token: foreignToken.toString('base64'),
        genTime: '2026-07-25T00:00:00.000Z',
        hashAlgorithm: 'sha256',
      },
    };
    const check = verifyRunAgainstAnchors(cannedRun, [record], { tsaCertPem });
    expect(check.ok).toBe(false);
    expect(check.rfc3161?.imprintOk).toBe(false);
    expect(check.problems.join(' ')).toMatch(/messageImprint mismatch/);
  });

  it('an unpinned TSA is reported as self-attested, never as external proof', () => {
    /*
     * The trap this product must not fall into twice: verifying a token
     * against the certificate inside that same token is the same closed loop
     * as verifying a run against its own embedded key. It must never be
     * presented as third-party proof.
     */
    const record: AnchorRecord = {
      version: 2,
      runId: canned.runId,
      runHash: canned.runHash,
      keyId: canned.keyId,
      signature: canned.signature,
      anchoredAt: '2026-07-25T00:00:00.000Z',
      proof: {
        type: 'rfc3161',
        token: anchorToken.toString('base64'),
        genTime: '2026-07-25T00:00:00.000Z',
        hashAlgorithm: 'sha256',
      },
    };
    const check = verifyRunAgainstAnchors(cannedRun, [record]); // no --tsa-cert
    expect(check.ok).toBe(true);
    expect(check.strength).toBe('self-attested'); // <-- NOT 'external'
    expect(check.messages.join(' ')).toMatch(/NOT pinned/);
  });

  it('a proof cannot be moved to another run, because the statement binds the run id', () => {
    // Same token, but presented for a run with a different id and hash.
    const otherRun = { ...cannedRun, id: 'some-other-run' } as Run;
    const record: AnchorRecord = {
      version: 2,
      runId: 'some-other-run',
      runHash: canned.runHash,
      keyId: canned.keyId,
      signature: canned.signature,
      anchoredAt: '2026-07-25T00:00:00.000Z',
      proof: {
        type: 'rfc3161',
        token: anchorToken.toString('base64'),
        genTime: '2026-07-25T00:00:00.000Z',
        hashAlgorithm: 'sha256',
      },
    };
    const check = verifyRunAgainstAnchors(otherRun, [record], { tsaCertPem });
    expect(check.ok).toBe(false);
    expect(check.rfc3161?.imprintOk).toBe(false);
  });

  it('the digest sent to a TSA leaks nothing about the run', () => {
    const statement = anchorStatement(genuine);
    const digest = anchorDigest(statement);
    expect(digest).toHaveLength(32);
    // Only the digest crosses the wire; the statement itself never does.
    const hex = digest.toString('hex');
    expect(hex).not.toContain(genuine.id);
    expect(statement.toString('utf8')).not.toContain('payments.refund');
    expect(statement.toString('utf8')).not.toContain('4471');
  });

  it('a run with no anchor at all is reported, not quietly passed', () => {
    const check = verifyRunAgainstAnchors(genuine, []);
    expect(check.found).toBe(0);
    expect(check.strength).toBe('none');
    expect(check.matched).toBe(false);
    expect(check.messages.join(' ')).toMatch(/no anchor record/);
  });
});
