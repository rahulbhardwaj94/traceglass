import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Step } from './model.js';
import { hashStep } from './integrity/hash.js';
import {
  JOURNAL_FORMAT_VERSION,
  findLiveRecording,
  journalLine,
  listLiveRecordings,
  liveRunFromJournal,
  readJournal,
} from './journal.js';
import { verifyRun } from './integrity/verify.js';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'tg-live-'));
  mkdirSync(dir, { recursive: true });
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** Append a hash-chained step to a journal exactly the way the SDK does. */
function appendStep(file: string, runId: string, index: number, prevHash: string, label: string) {
  const step: Step = {
    id: `${runId}:${index}`,
    runId,
    index,
    type: index === 0 ? 'user_input' : 'tool_call',
    label,
    startedAt: new Date(Date.now() + index * 1000).toISOString(),
    durationMs: 5,
    tokens: 10,
    cost: 1,
    ...(index > 0 ? { toolName: 'get_status' } : {}),
    spanId: `s${index}`,
    hash: '',
    prevHash,
  };
  step.hash = hashStep(step, prevHash);
  appendFileSync(file, journalLine({ kind: 'step', step }));
  return step.hash;
}

function startJournal(runId: string, name = 'live run'): string {
  const file = join(dir, `${runId}.jsonl`);
  writeFileSync(
    file,
    journalLine({
      kind: 'meta',
      formatVersion: JOURNAL_FORMAT_VERSION,
      id: runId,
      name,
      currency: 'USD',
      startedAt: new Date().toISOString(),
    }),
  );
  return file;
}

describe('live recordings (tail mode)', () => {
  it('lists in-progress recordings from their journals', () => {
    const file = startJournal('live-1', 'collections agent');
    appendStep(file, 'live-1', 0, '', 'start');
    const live = listLiveRecordings(dir);
    expect(live).toHaveLength(1);
    expect(live[0]!.runId).toBe('live-1');
    expect(live[0]!.name).toBe('collections agent');
    expect(live[0]!.steps).toBe(1);
    expect(live[0]!.ended).toBe(false);
  });

  it('reflects steps as they are appended — the stream is the journal', () => {
    const file = startJournal('live-2');
    let prev = appendStep(file, 'live-2', 0, '', 'first');
    expect(listLiveRecordings(dir)[0]!.steps).toBe(1);

    prev = appendStep(file, 'live-2', 1, prev, 'second');
    appendStep(file, 'live-2', 2, prev, 'third');
    expect(listLiveRecordings(dir)[0]!.steps).toBe(3);

    const run = liveRunFromJournal(readJournal(file));
    expect(run.status).toBe('running');
    expect(run.runHash).toBe(''); // not yet anchored
    expect(run.totals.steps).toBe(3);
    expect(run.totals.cost).toBe(3);
    expect(run.steps.map((s) => s.label)).toEqual(['first', 'second', 'third']);
  });

  it('the partial chain still verifies up to the latest step', () => {
    const file = startJournal('live-3');
    let prev = appendStep(file, 'live-3', 0, '', 'a');
    prev = appendStep(file, 'live-3', 1, prev, 'b');
    const run = liveRunFromJournal(readJournal(file));
    // runHash is empty by design, so seal it to check the chain itself.
    const sealed = { ...run, runHash: run.steps[run.steps.length - 1]!.hash };
    expect(verifyRun(sealed).ok).toBe(true);
  });

  it('surfaces warnings mid-flight (the loop fires before the run ends)', () => {
    const file = startJournal('live-4');
    let prev = appendStep(file, 'live-4', 0, '', 'start');
    // Three identical consecutive tool calls trip the loop detector.
    for (let i = 1; i <= 3; i++) prev = appendStep(file, 'live-4', i, prev, 'Tool: get_status');
    const run = liveRunFromJournal(readJournal(file));
    expect(run.warnings.some((w) => w.kind === 'loop')).toBe(true);
  });

  it('findLiveRecording locates by id and returns null when absent', () => {
    const file = startJournal('live-5');
    appendStep(file, 'live-5', 0, '', 'x');
    expect(findLiveRecording('live-5', dir)!.runId).toBe('live-5');
    expect(findLiveRecording('nope', dir)).toBeNull();
  });

  it('a half-written trailing line is skipped, not fatal', () => {
    const file = startJournal('live-6');
    appendStep(file, 'live-6', 0, '', 'ok');
    appendFileSync(file, '{"kind":"step","step":{"id":"trunc'); // torn mid-append
    // The torn journal is skipped rather than crashing discovery.
    expect(listLiveRecordings(dir)).toEqual([]);
  });

  it('an empty or missing journal dir yields no recordings', () => {
    expect(listLiveRecordings(join(dir, 'nothing-here'))).toEqual([]);
    expect(listLiveRecordings(dir)).toEqual([]);
  });

  it('marks a recording ended once the end record lands', () => {
    const file = startJournal('live-7');
    appendStep(file, 'live-7', 0, '', 'x');
    appendFileSync(file, journalLine({ kind: 'end', status: 'completed' }));
    expect(listLiveRecordings(dir)[0]!.ended).toBe(true);
  });
});
