import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Step } from './model.js';
import { withCommitments } from './redact/redact.js';
import { hashStep } from './integrity/hash.js';
import { verifyRun } from './integrity/verify.js';
import {
  JOURNAL_FORMAT_VERSION,
  finalizeJournal,
  journalLine,
  listLiveRecordings,
  liveRunFromJournal,
  readJournal,
} from './journal.js';

/**
 * ADVERSARIAL SUITE — journal poisoning (attack 8).
 *
 * The journal is the weakest link by construction: it is a plain JSONL file in
 * a well-known directory, written line-by-line while a run is in flight, and
 * anything on the box can edit it. The claim is that a poisoned journal can
 * never be imported as trustworthy evidence. Recovery honours that. The LIVE
 * path does not.
 */

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'tg-journal-attack-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Build a well-formed, correctly-chained journal for `runId`. */
function honestJournal(runId: string, amounts: number[]): string {
  const lines = [
    journalLine({
      kind: 'meta',
      formatVersion: JOURNAL_FORMAT_VERSION,
      id: runId,
      name: 'agent run',
      currency: 'USD',
      startedAt: '2026-01-01T00:00:00.000Z',
    }),
  ];
  let prevHash = '';
  amounts.forEach((amount, index) => {
    const base = withCommitments({
      id: `${runId}:${index}`,
      runId,
      index,
      type: 'tool_call' as const,
      label: `pay ${amount}`,
      startedAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
      durationMs: 1,
      tokens: 1,
      cost: 1,
      toolName: 'payments.transfer',
      input: { amount },
      spanId: `span-${index}`,
      hash: '',
      prevHash,
    }) as Step;
    base.hash = hashStep(base, prevHash);
    prevHash = base.hash;
    lines.push(journalLine({ kind: 'step', step: base }));
  });
  lines.push(journalLine({ kind: 'end', status: 'completed' }));
  return lines.join('');
}

function write(name: string, contents: string): string {
  const file = join(dir, `${name}.jsonl`);
  writeFileSync(file, contents);
  return file;
}

describe('ATTACK 8: recovery refuses poisoned journals', () => {
  it('an honest journal finalizes into a verifying run (baseline)', () => {
    const file = write('honest', honestJournal('honest', [10, 20, 30]));
    const run = finalizeJournal(readJournal(file));
    expect(run.status).toBe('completed');
    expect(run.totals.steps).toBe(3);
    expect(verifyRun(run).ok).toBe(true);
  });

  it('REFUSES a journal whose step lines were reordered', () => {
    const lines = honestJournal('reorder', [10, 20, 30]).trimEnd().split('\n');
    const poisoned = [lines[0]!, lines[2]!, lines[1]!, lines[3]!, lines[4]!].join('\n') + '\n';
    const file = write('reorder', poisoned);
    expect(() => finalizeJournal(readJournal(file))).toThrow(/fails integrity/);
    expect(() => finalizeJournal(readJournal(file))).toThrow(/chain broken/);
  });

  it('REFUSES a journal whose payload was edited in place', () => {
    // The chain hashes commitments, so editing a raw amount does not move any
    // hash. The commitment check inside verifyRun is what stops it.
    const honest = honestJournal('edited', [10, 500000]);
    const file = write('edited', honest.replace('"amount":500000', '"amount":1'));
    expect(() => finalizeJournal(readJournal(file))).toThrow(/fails integrity/);
    expect(() => finalizeJournal(readJournal(file))).toThrow(/does not match its commitment/);
  });

  it('REFUSES a journal with an injected step', () => {
    const lines = honestJournal('inject', [10, 20]).trimEnd().split('\n');
    const forged = JSON.parse(lines[1]!) as { step: Step };
    forged.step = { ...forged.step, id: 'inject:99', label: 'fabricated', input: { amount: 0 } };
    const file = write(
      'inject',
      [lines[0]!, JSON.stringify(forged), ...lines.slice(2)].join('\n') + '\n',
    );
    expect(() => finalizeJournal(readJournal(file))).toThrow(/fails integrity/);
  });

  it('REFUSES a journal whose hashes were blanked out', () => {
    const lines = honestJournal('blank', [10, 20]).trimEnd().split('\n');
    const broken = lines
      .map((l) => (l.includes('"kind":"step"') ? l.replace(/"hash":"[0-9a-f]{64}"/, '"hash":""') : l))
      .join('\n');
    const file = write('blank', broken + '\n');
    expect(() => finalizeJournal(readJournal(file))).toThrow(/fails integrity/);
  });

  it('REFUSES a journal with no meta line, and one with a bumped format version', () => {
    const lines = honestJournal('nometa', [10]).trimEnd().split('\n');
    const noMeta = write('nometa', lines.slice(1).join('\n') + '\n');
    expect(() => readJournal(noMeta)).toThrow(/no meta line/);

    const wrongVersion = write(
      'wrongversion',
      honestJournal('wrongversion', [10]).replace('"formatVersion":1', '"formatVersion":99'),
    );
    expect(() => readJournal(wrongVersion)).toThrow();
  });

  it('REFUSES a journal with zero steps rather than storing an empty "run"', () => {
    const lines = honestJournal('empty', [10]).trimEnd().split('\n');
    const file = write('empty', [lines[0]!, lines[2]!].join('\n') + '\n');
    expect(() => finalizeJournal(readJournal(file))).toThrow(/no steps/);
  });

  it('a journal with no end record finalizes as FAILED, never as completed', () => {
    // An attacker who kills the process cannot pass the partial run off as a
    // clean completion.
    const lines = honestJournal('crashed', [10, 20]).trimEnd().split('\n');
    const file = write('crashed', lines.slice(0, -1).join('\n') + '\n');
    const run = finalizeJournal(readJournal(file));
    expect(run.status).toBe('failed');
    expect(verifyRun(run).ok).toBe(true);
  });

  it('an end record cannot claim status "running"', () => {
    const file = write(
      'runningend',
      honestJournal('runningend', [10]).replace('"status":"completed"', '"status":"running"'),
    );
    expect(() => readJournal(file)).toThrow();
  });

  it('VULNERABILITY: a TRUNCATED journal finalizes clean, silently losing steps', () => {
    /*
     * VULNERABILITY: nothing in the journal commits to how many steps it should
     * contain, so any PREFIX of a valid journal is itself a valid journal.
     * Deleting trailing step lines produces a run that finalizes, verifies
     * "chain intact", and gets stored as evidence.
     *
     * REAL-WORLD CONSEQUENCE: the journal sits in a predictable path
     * (~/.traceglass/journal/<runId>.jsonl) and is written while the run is
     * still going. An agent — or anything else on the box — can delete the
     * lines recording the destructive call it just made, and `traceglass
     * recover` will import the sanitized remainder as a verifying record. The
     * only tell is that the run is marked `failed`, which is exactly what a
     * genuine crash looks like.
     *
     * WHAT SHOULD HAPPEN: the meta line should carry a monotonic counter, or
     * `end` should record the expected step count, so a missing tail is
     * detectable.
     */
    const lines = honestJournal('truncated', [10, 20, 500000]).trimEnd().split('\n');
    const full = finalizeJournal(readJournal(write('truncated-full', lines.join('\n') + '\n')));
    expect(full.totals.steps).toBe(3);

    // Delete the incriminating final step (and the end record with it).
    const file = write('truncated', lines.slice(0, 3).join('\n') + '\n');
    const run = finalizeJournal(readJournal(file));
    expect(run.totals.steps).toBe(2); // <-- a step vanished
    expect(verifyRun(run).ok).toBe(true); // <-- and the record calls itself intact
    expect(verifyRun(run).message).toContain('chain intact');
    expect(JSON.stringify(run)).not.toContain('500000');
    expect(run.status).toBe('failed'); // indistinguishable from a real crash
  });

  it('VULNERABILITY: liveRunFromJournal performs NO integrity check at all', () => {
    /*
     * VULNERABILITY: `finalizeJournal` ends with `verifyRun` and throws on
     * failure. `liveRunFromJournal` — the function behind `GET /api/live/:id`
     * and `traceglass tail` — does not verify anything. It assembles whatever
     * the file says and hands it back.
     *
     * REAL-WORLD CONSEQUENCE: the live dashboard and the tail CLI are the
     * surfaces an operator watches DURING an incident, which is exactly when
     * they most need the record to be trustworthy. A poisoned journal is
     * rendered as a normal in-flight run, with no warning, over an API whose
     * response is flagged `live: true`. The same bytes are refused by
     * `recover` seconds later — so the product enforces its guarantee on the
     * cold path and drops it on the hot one.
     *
     * WHAT SHOULD HAPPEN: liveRunFromJournal should run verifyRun over the
     * steps recorded so far and surface the result (the chain IS sealed up to
     * the latest step, so this is checkable), and the API should refuse or
     * clearly mark an unverifiable live run.
     */
    // (a) Reordered steps — refused by recovery, accepted live.
    const reorderLines = honestJournal('live-reorder', [10, 20, 30]).trimEnd().split('\n');
    const reordered = write(
      'live-reorder',
      [reorderLines[0]!, reorderLines[2]!, reorderLines[1]!, reorderLines[3]!].join('\n') + '\n',
    );
    expect(() => finalizeJournal(readJournal(reordered))).toThrow(/fails integrity/);
    const liveReordered = liveRunFromJournal(readJournal(reordered)); // <-- THE HOLE
    expect(liveReordered.steps).toHaveLength(3);
    expect(liveReordered.status).toBe('running');
    // Proof it really is broken, if anyone had bothered to look:
    expect(verifyRun({ ...liveReordered, runHash: liveReordered.steps.at(-1)!.hash }).ok).toBe(
      false,
    );

    // (b) Edited payload — refused by recovery, served live with the lie intact.
    const editedFile = write(
      'live-edited',
      honestJournal('live-edited', [500000]).replace('"amount":500000', '"amount":1'),
    );
    expect(() => finalizeJournal(readJournal(editedFile))).toThrow(/does not match its commitment/);
    const liveEdited = liveRunFromJournal(readJournal(editedFile)); // <-- THE HOLE
    expect(liveEdited.steps[0]!.input).toEqual({ amount: 1 });
  });

  it('VULNERABILITY: listLiveRecordings advertises a poisoned journal as a normal run', () => {
    /*
     * VULNERABILITY: discovery (which backs `GET /api/live` and
     * `traceglass tail --list`) only requires that the file PARSES. A journal
     * whose chain is broken is listed alongside genuine recordings with no
     * distinguishing mark.
     *
     * REAL-WORLD CONSEQUENCE: an attacker can drop a wholly fabricated journal
     * into ~/.traceglass/journal/ and have it appear in the operator's live
     * view as an agent run that is happening right now.
     */
    const listDir = mkdtempSync(join(tmpdir(), 'tg-live-list-'));
    try {
      // A fabricated run that never happened, with deliberately wrong hashes.
      const fabricated = honestJournal('ghost', [1])
        .replace(/"hash":"[0-9a-f]{64}"/g, '"hash":"' + 'de'.repeat(32) + '"')
        .trimEnd()
        .split('\n')
        .slice(0, 2)
        .join('\n');
      writeFileSync(join(listDir, 'ghost.jsonl'), fabricated + '\n');

      const listed = listLiveRecordings(listDir);
      expect(listed).toHaveLength(1); // <-- THE HOLE
      expect(listed[0]!.runId).toBe('ghost');
      expect(listed[0]!.steps).toBe(1);
      // Nothing in the LiveRecording shape can even express "unverified".
      expect(Object.keys(listed[0]!)).not.toContain('verified');
    } finally {
      rmSync(listDir, { recursive: true, force: true });
    }
  });

  it('a half-written trailing line is skipped, not treated as corruption', () => {
    // Benign case that must NOT be mistaken for an attack: the SDK appends
    // line-by-line, so a reader can catch a partial final line.
    const listDir = mkdtempSync(join(tmpdir(), 'tg-live-partial-'));
    try {
      const contents = honestJournal('partial', [10, 20]);
      writeFileSync(join(listDir, 'partial.jsonl'), contents.slice(0, contents.length - 30));
      // Discovery skips the file entirely rather than reporting a bogus run.
      expect(listLiveRecordings(listDir)).toHaveLength(0);
    } finally {
      rmSync(listDir, { recursive: true, force: true });
    }
  });

  it('the recovered run’s anchor is the last step hash, not an attacker-chosen value', () => {
    // finalizeJournal derives runHash from the steps; a journal cannot smuggle
    // its own anchor in because there is no field for one.
    const file = write('anchor', honestJournal('anchor', [10, 20]));
    const contents = readJournal(file);
    const run = finalizeJournal(contents);
    expect(run.runHash).toBe(contents.steps[contents.steps.length - 1]!.hash);
    expect(readFileSync(file, 'utf8')).not.toContain('runHash');
  });
});
