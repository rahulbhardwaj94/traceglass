import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RunStore, finalizeJournal, readJournal, verifyRun, verifyRunFull } from '@traceglass/core';
import { startRecording } from './recorder.js';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-sdk-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe('startRecording', () => {
  it('fixes the chain at capture time: earlier hashes never change', () => {
    const rec = startRecording({ name: 'r', dir: null });
    const s0 = rec.step({ type: 'user_input', label: 'ask' });
    const h0 = s0.hash;
    rec.step({ type: 'tool_call', toolName: 'db', label: 'Tool: db', output: { rows: 3 } });
    const s2 = rec.step({ type: 'final_output', label: 'answer' });
    expect(s0.hash).toBe(h0);
    expect(s2.prevHash).not.toBe('');
    expect(s2.index).toBe(2);
  });

  it('preserves recorded order even with out-of-order startedAt values', async () => {
    const rec = startRecording({ name: 'r', dir: null });
    rec.step({ type: 'user_input', label: 'first', startedAt: '2026-01-02T00:00:00.000Z' });
    rec.step({ type: 'final_output', label: 'second', startedAt: '2026-01-01T00:00:00.000Z' });
    const run = await rec.end();
    expect(run.steps.map((s) => s.label)).toEqual(['first', 'second']);
    expect(verifyRun(run).ok).toBe(true);
  });

  it('journals during recording, saves + cleans up on end()', async () => {
    const rec = startRecording({ name: 'journaled', dir: home, id: 'run-j' });
    rec.step({ type: 'user_input', label: 'go' });
    const journal = join(home, 'journal', 'run-j.jsonl');
    expect(existsSync(journal)).toBe(true);
    rec.step({ type: 'final_output', label: 'done' });
    const run = await rec.end();
    expect(existsSync(journal)).toBe(false);
    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const stored = store.getRun('run-j');
    store.close();
    expect(stored).not.toBeNull();
    expect(verifyRunFull(stored!).ok).toBe(true);
    expect(run.totals.steps).toBe(2);
  });

  it('a crashed recording is recoverable as a verifying failed run', () => {
    const rec = startRecording({ name: 'crashy', dir: home, id: 'run-c' });
    rec.step({ type: 'user_input', label: 'go' });
    rec.step({ type: 'tool_call', toolName: 'x', label: 'Tool: x', cost: 2 });
    // No end(): simulate a crash by just abandoning the recorder.
    const journal = join(home, 'journal', 'run-c.jsonl');
    const run = finalizeJournal(readJournal(journal));
    expect(run.status).toBe('failed');
    expect(run.totals.steps).toBe(2);
    expect(verifyRun(run).ok).toBe(true);
  });

  it('derives failed status from an error step', async () => {
    const rec = startRecording({ name: 'r', dir: null });
    rec.step({ type: 'user_input', label: 'go' });
    rec.step({ type: 'error', label: 'boom' });
    const run = await rec.end();
    expect(run.status).toBe('failed');
    expect(run.warnings.some((w) => w.kind === 'error')).toBe(true);
  });

  it('refuses steps after end and empty recordings', async () => {
    const rec = startRecording({ name: 'r', dir: null });
    await expect(rec.end()).rejects.toThrow(/no steps/);
    const rec2 = startRecording({ name: 'r2', dir: null });
    rec2.step({ type: 'user_input', label: 'go' });
    await rec2.end();
    expect(() => rec2.step({ type: 'plan', label: 'late' })).toThrow(/already ended/);
  });
});
