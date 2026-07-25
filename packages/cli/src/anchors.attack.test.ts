import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RunStore, ingestAndFinalize, verifyRunFull, type Run } from '@traceglass/core';
import { startRecording } from '@traceglass/sdk';
import { FileAnchorSink, anchorRecordForRun, type AnchorRecord } from './anchors.js';
import { generateKeys, maybeSign } from './keys.js';

/**
 * ADVERSARIAL SUITE — anchor forgery (attack 3).
 *
 * The pitch for anchors is that they externalize a run's integrity anchor so it
 * can be pinned somewhere the store cannot touch — "a verifier later compares a
 * run's recomputed anchor against this out-of-band copy" (anchors.ts).
 *
 * These tests ask the obvious attacker question: what happens if I write into
 * that file myself? The answer is that anchors.jsonl is currently WRITE-ONLY.
 * Nothing in the codebase ever reads a record back to compare it against a run,
 * so a forged entry is not merely undetected — there is no detector.
 */

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

  it('VULNERABILITY: a hand-written anchor for a run that never existed is accepted', async () => {
    /*
     * VULNERABILITY: anchors.jsonl is append-only text written by the CLI with
     * appendFileSync. It carries no signature over its own contents, no
     * sequence number, and no chaining between entries. An attacker with write
     * access to the file — the same access needed to edit the store — can
     * fabricate an entry for a run that was never recorded.
     *
     * REAL-WORLD CONSEQUENCE: the anchors file is what the docs tell operators
     * to push to WORM storage and treat as the out-of-band source of truth. An
     * attacker who fabricates an entry can later produce a matching forged
     * evidence file (see the key-substitution attack in
     * integrity.attack.test.ts) and point at "the anchor we pinned in S3" as
     * independent corroboration. The forgery is corroborating itself.
     *
     * WHAT SHOULD HAPPEN: anchor records should be signed, and the file should
     * chain each record to the previous one so insertions and rewrites are
     * detectable.
     */
    const forged: AnchorRecord = {
      version: 1,
      runId: 'run-that-never-happened',
      runHash: 'f'.repeat(64),
      keyId: '0123456789abcdef',
      signature: Buffer.from('not a real signature').toString('base64'),
      anchoredAt: '2026-01-01T00:00:00.000Z',
    };
    appendFileSync(anchorsFile, JSON.stringify(forged) + '\n');

    // It is indistinguishable from a genuine record in every observable way.
    const records = readAnchors();
    const found = records.find((r) => r.runId === 'run-that-never-happened');
    expect(found).toBeDefined(); // <-- THE HOLE
    expect(found!.version).toBe(1);
    // The run it claims to anchor does not exist anywhere.
    expect(store.getRun('run-that-never-happened')).toBeNull();

    // And the ONLY consumer of this file treats it as authoritative.
    const sink = new FileAnchorSink(anchorsFile);
    expect(sink.existingRunIds().has('run-that-never-happened')).toBe(true);
  });

  it('VULNERABILITY: no code path anywhere verifies a run against its anchor', async () => {
    /*
     * VULNERABILITY: this is the root of attack 3. `FileAnchorSink` has
     * `append()` and `existingRunIds()`. There is no `verify()`, no CLI command
     * that reads anchors and compares them to stored runs, and `traceglass
     * verify` never opens the file. The anchors are written, and then nothing
     * ever looks at them again.
     *
     * REAL-WORLD CONSEQUENCE: the anchoring feature currently provides zero
     * automated detection. If a run's hash is silently changed in the store,
     * the pinned anchor will disagree — and nobody will ever find out, because
     * no code performs the comparison. Detecting the very tampering anchors
     * exist to catch requires an operator to diff two files by hand.
     *
     * WHAT SHOULD HAPPEN: ship `traceglass verify --anchors <file>` that
     * recomputes each run's anchor and reports disagreements, and wire it into
     * the `check` command.
     */
    const sink = new FileAnchorSink(anchorsFile);
    const surface = Object.getOwnPropertyNames(Object.getPrototypeOf(sink));
    expect(surface.sort()).toEqual(['append', 'constructor', 'existingRunIds']); // <-- no verify

    // Demonstrate the miss end to end: alter the stored run's anchor, then show
    // that everything the product offers still reports success.
    const tamperedRun: Run = { ...genuine, runHash: 'a'.repeat(64) };
    const anchored = readAnchors().find((r) => r.runId === 'anchored-run')!;
    expect(anchored.runHash).not.toBe(tamperedRun.runHash); // the anchor DISAGREES

    // The disagreement is real and would be trivially detectable...
    expect(anchored.runHash).toBe(genuine.runHash);
    // ...but nothing does the comparison, so the only thing that catches this
    // tampered run is the signature — not the anchor.
    expect(verifyRunFull(tamperedRun).signature.ok).toBe(false);
  });

  it('VULNERABILITY: a pre-registered anchor SUPPRESSES the genuine one', async () => {
    /*
     * VULNERABILITY: `existingRunIds()` dedupes purely by runId, so
     * `traceglass anchor` skips any run already named in the file — regardless
     * of whether the recorded runHash matches.
     *
     * REAL-WORLD CONSEQUENCE: an attacker who can guess a run id (they are
     * derived from session logs and SDK timestamps, not secrets) writes a bogus
     * anchor for it FIRST. When the operator later runs `traceglass anchor
     * --all`, the genuine anchor is silently skipped and the output says
     * "(1 already anchored)" — reported as a successful no-op. The WORM copy
     * now permanently holds the attacker's hash for that run, and the real one
     * was never written.
     *
     * WHAT SHOULD HAPPEN: dedupe on (runId, runHash). A runId already present
     * with a DIFFERENT hash is a conflict that must be surfaced loudly, not
     * skipped.
     */
    const suppressFile = join(home, 'suppressed.jsonl');
    // The attacker gets there first with a wrong hash for a real run id.
    writeFileSync(
      suppressFile,
      JSON.stringify({
        version: 1,
        runId: 'anchored-run',
        runHash: 'b'.repeat(64), // NOT the genuine anchor
        anchoredAt: '2020-01-01T00:00:00.000Z',
      }) + '\n',
    );

    // Now the operator anchors for real. This mirrors bin.ts `anchor --all`.
    const sink = new FileAnchorSink(suppressFile);
    const existing = sink.existingRunIds();
    const fresh = [genuine].filter((r) => !existing.has(r.id));
    await sink.append(fresh.map(anchorRecordForRun));

    expect(fresh).toHaveLength(0); // <-- the genuine anchor was never written
    const records = readFileSync(suppressFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(records).toHaveLength(1);
    expect(records[0].runHash).toBe('b'.repeat(64)); // only the attacker's hash survives
    expect(records[0].runHash).not.toBe(genuine.runHash);
  });

  it('VULNERABILITY: malformed lines are silently skipped, so entries can be hidden', async () => {
    /*
     * VULNERABILITY: `existingRunIds()` swallows JSON parse errors ("Skip
     * malformed lines; they don't block new anchors"). Combined with the
     * absence of any chaining, this means an attacker can corrupt or delete a
     * specific anchor line and the file still reads as valid — the record
     * simply ceases to exist, with nothing to indicate a gap.
     *
     * REAL-WORLD CONSEQUENCE: deletion from an append-only evidence file is
     * undetectable. The lenient parse is reasonable for a writer; it is
     * dangerous for something described as the out-of-band source of truth.
     *
     * WHAT SHOULD HAPPEN: a reader that verifies (which does not exist yet)
     * must treat an unparseable line as an integrity failure, and records
     * should chain so a removal breaks the sequence.
     */
    const tamperFile = join(home, 'tampered-anchors.jsonl');
    writeFileSync(
      tamperFile,
      [
        JSON.stringify({ version: 1, runId: 'run-a', runHash: 'a'.repeat(64), anchoredAt: 'x' }),
        JSON.stringify({ version: 1, runId: 'run-b', runHash: 'b'.repeat(64), anchoredAt: 'x' }),
        JSON.stringify({ version: 1, runId: 'run-c', runHash: 'c'.repeat(64), anchoredAt: 'x' }),
      ].join('\n') + '\n',
    );
    expect(new FileAnchorSink(tamperFile).existingRunIds().size).toBe(3);

    // Corrupt the middle record. The file still parses "fine" — one short.
    const corrupted = readFileSync(tamperFile, 'utf8').replace(/^.*run-b.*$/m, '{"runId": broken');
    writeFileSync(tamperFile, corrupted);
    const ids = new FileAnchorSink(tamperFile).existingRunIds();
    expect(ids.size).toBe(2); // <-- THE HOLE: run-b vanished, no error raised
    expect(ids.has('run-b')).toBe(false);

    // Outright deleting the line is likewise invisible.
    writeFileSync(tamperFile, corrupted.split('\n').filter((l) => !l.includes('broken')).join('\n'));
    expect(new FileAnchorSink(tamperFile).existingRunIds().size).toBe(2);
  });

  it('a record without a runId is ignored, so it cannot poison the dedupe set', () => {
    const f = join(home, 'noid.jsonl');
    writeFileSync(f, JSON.stringify({ version: 1, runHash: 'x'.repeat(64) }) + '\n');
    expect(new FileAnchorSink(f).existingRunIds().size).toBe(0);
  });

  it('anchoring an unsigned run records no signature to borrow', () => {
    // Pinning a property that matters: an anchor cannot invent a signature for
    // a run that never had one.
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
    // anchorRecordForRun derives runHash from the run object; there is no
    // parameter for it, which closes the most obvious forgery route through the
    // supported API (as opposed to editing the file directly).
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
