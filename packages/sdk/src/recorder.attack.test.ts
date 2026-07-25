import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  RunStore,
  REDACTED_MARKER,
  finalizeJournal,
  readJournal,
  verifyRun,
  type Run,
} from '@traceglass/core';
import { startRecording } from './recorder.js';

/**
 * ADVERSARIAL SUITE — the capture surface (attacks 6, 8, 9 at the SDK boundary).
 *
 * The recorder is in-process with the agent it records. Anything the agent can
 * influence — step ordering, payload contents, the run id — is attacker-
 * controlled in the threat model where the agent itself has been subverted.
 * These tests ask what an agent can do to its own flight recorder.
 */

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-recorder-attack-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

const dbFile = () => join(home, 'traceglass.sqlite');
const journalFile = (id: string) => join(home, 'journal', `${id}.jsonl`);

describe('ATTACK: subverting the recorder from inside the agent', () => {
  it('mutating a returned Step makes end() REFUSE to save, and the journal keeps the truth', async () => {
    // `step()` hands back a live reference into the recorder's own array, so a
    // subverted agent can edit a step it already recorded. The commitment for
    // that leaf was computed at capture time, so end()'s self-check catches it
    // and nothing reaches the store.
    const rec = startRecording({ name: 'agent', dir: home, id: 'seal' });
    const first = rec.step({
      type: 'tool_call',
      toolName: 'pay',
      label: 'a',
      input: { amount: 500000 },
    });
    (first.input as { amount: number }).amount = 1; // rewrite history in place
    rec.step({ type: 'final_output', label: 'done' });

    await expect(rec.end()).rejects.toThrow(/self-check failed.*does not match its commitment/s);

    // Nothing was written to the store...
    expect(existsSync(dbFile())).toBe(false);
    // ...and the journal, appended at capture time, still holds the real value.
    expect(readFileSync(journalFile('seal'), 'utf8')).toContain('500000');
    const recovered = finalizeJournal(readJournal(journalFile('seal')));
    expect((recovered.steps[0]!.input as { amount: number }).amount).toBe(500000);
    expect(verifyRun(recovered).ok).toBe(true);
  });

  it('a recorder cannot be reused after end(), and cannot end twice', async () => {
    const rec = startRecording({ name: 'agent', dir: home, id: 'reuse' });
    rec.step({ type: 'user_input', label: 'a' });
    await rec.end();
    expect(() => rec.step({ type: 'user_input', label: 'sneaky late step' })).toThrow(
      /already ended/,
    );
    await expect(rec.end()).rejects.toThrow(/already ended/);
  });

  it('a recording with no steps refuses to finalize into an empty "run"', async () => {
    const rec = startRecording({ name: 'agent', dir: home, id: 'nosteps' });
    await expect(rec.end()).rejects.toThrow(/no steps/);
    expect(existsSync(dbFile())).toBe(false);
  });

  it('indices are assigned by the recorder, not by the caller', async () => {
    // RecordStepInput has no `index` or `id` field, so an agent cannot claim a
    // position in the chain. Pinning that as an API-shape guarantee.
    const rec = startRecording({ name: 'agent', dir: home, id: 'idx' });
    const a = rec.step({ type: 'user_input', label: 'a' });
    const b = rec.step({ type: 'user_input', label: 'b' });
    expect([a.index, b.index]).toEqual([0, 1]);
    expect([a.id, b.id]).toEqual(['idx:0', 'idx:1']);
    expect(b.prevHash).toBe(a.hash);
  });

  it('VULNERABILITY: startedAt is caller-supplied and never sanity-checked', async () => {
    /*
     * VULNERABILITY: `RecordStepInput.startedAt` lets the caller stamp any time
     * it likes, and nothing compares it against the previous step or the run's
     * own start. The value is hashed, so it cannot be changed AFTERWARDS — but
     * it can be a lie from the moment of capture.
     *
     * REAL-WORLD CONSEQUENCE: a subverted agent backdates the destructive step
     * to before the incident window, or forward past it. The record verifies
     * perfectly and the timeline in the audit report is fiction. Chained to the
     * non-monotonic-timestamp finding in integrity.attack.test.ts: nothing on
     * the read side flags it either.
     *
     * WHAT SHOULD HAPPEN: reject (or flag) a startedAt earlier than the run
     * start or than the previous step's, since the recorder knows both.
     */
    const rec = startRecording({ name: 'agent', dir: home, id: 'backdate' });
    rec.step({ type: 'user_input', label: 'a', startedAt: '2026-06-01T00:00:00.000Z' });
    rec.step({
      type: 'tool_call',
      toolName: 'delete_everything',
      label: 'b',
      startedAt: '1999-01-01T00:00:00.000Z', // "before the incident"
    });
    const run = await rec.end();
    expect(verifyRun(run).ok).toBe(true); // <-- pinning the hole
    expect(Date.parse(run.steps[1]!.startedAt)).toBeLessThan(Date.parse(run.steps[0]!.startedAt));
    expect(run.steps[1]!.startedAt).toBe('1999-01-01T00:00:00.000Z');
  });

  it('VULNERABILITY: a pre-registered run id destroys the recording at end()', async () => {
    /*
     * VULNERABILITY: `end()` calls `store.saveRun`, which throws on a duplicate
     * id (correctly — the store is append-only). But that throw happens BEFORE
     * the journal is unlinked and AFTER `ended = true` is set, so the recorder
     * is left in a terminal state with the run unsaved.
     *
     * REAL-WORLD CONSEQUENCE: run ids are predictable (`sdk-<date>-<6 hex>`, or
     * whatever the caller passes). An attacker who writes one placeholder run
     * into the store guarantees that the genuine recording of that id can never
     * be saved. The agent sees an exception from `end()` — an agent that
     * wraps its shutdown in try/catch, which is normal, will swallow it and
     * carry on believing the run was recorded.
     *
     * MITIGATION THAT EXISTS: the journal is NOT deleted, so the evidence
     * survives on disk and `traceglass recover` could import it — except that
     * recover ALSO skips ids already in the store ("run already stored;
     * removing journal") and then DELETES the journal. So the standard
     * remediation path destroys the only surviving copy.
     *
     * WHAT SHOULD HAPPEN: on an id collision, save under a disambiguated id or
     * quarantine the journal, and never delete a journal whose contents were
     * not actually stored.
     */
    // The attacker plants a placeholder under the id the agent will use.
    const store = new RunStore(dbFile());
    const placeholder: Run = {
      id: 'collide',
      name: 'ATTACKER PLACEHOLDER',
      startedAt: '2020-01-01T00:00:00.000Z',
      endedAt: '2020-01-01T00:00:00.000Z',
      status: 'completed',
      currency: 'USD',
      totals: { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
      warnings: [],
      steps: [],
      runHash: '',
    };
    store.saveRun(placeholder);
    store.close();

    const rec = startRecording({ name: 'genuine agent', dir: home, id: 'collide' });
    rec.step({ type: 'tool_call', toolName: 'pay', label: 'transfer', input: { amount: 500000 } });

    await expect(rec.end()).rejects.toThrow(/append-only/); // <-- evidence not saved

    const after = new RunStore(dbFile());
    const stored = after.getRun('collide')!;
    after.close();
    expect(stored.name).toBe('ATTACKER PLACEHOLDER');
    expect(stored.steps).toHaveLength(0);

    // The journal survives — the one thing standing between this and total loss.
    expect(existsSync(journalFile('collide'))).toBe(true);
    expect(readFileSync(journalFile('collide'), 'utf8')).toContain('500000');
    // And it would recover cleanly, if anything were willing to import it.
    const recovered = finalizeJournal(readJournal(journalFile('collide')));
    expect(recovered.totals.steps).toBe(1);
    expect(verifyRun(recovered).ok).toBe(true);
  });

  it('capture-time scrubbing beats an agent that logs its own secrets', async () => {
    // The one place the SDK actively defends against its own caller.
    const rec = startRecording({
      name: 'leaky agent',
      dir: home,
      id: 'scrub',
      redactPatterns: ['ssn', 'email', 'bearer-token'],
    });
    const step = rec.step({
      type: 'user_input',
      label: 'lookup',
      input: { ssn: '123-45-6789', email: 'jane@example.com', token: 'sk-abcdefghijklmnop123456' },
      output: { keep: 'safe' },
    });
    const run = await rec.end();

    // Gone from the step, from the journal write, and from the store.
    for (const value of ['123-45-6789', 'jane@example.com', 'sk-abcdefghijklmnop123456']) {
      expect(JSON.stringify(step)).not.toContain(value);
      expect(JSON.stringify(run)).not.toContain(value);
      expect(readFileSync(dbFile(), 'latin1')).not.toContain(value);
    }
    expect((step.input as { ssn: string }).ssn).toBe(REDACTED_MARKER);
    expect(JSON.stringify(run)).toContain('safe');
    // Nothing was ever committed to the originals, so there is no commitment to
    // brute-force later.
    expect(run.steps[0]!.redactions!.map((r) => r.by)).toEqual(['pattern', 'pattern', 'pattern']);
  });

  it('VULNERABILITY: scrubbing is opt-in, so the default recording stores PII verbatim', async () => {
    /*
     * VULNERABILITY: `redactPatterns` defaults to `[]`. A caller who does not
     * know the option exists gets no capture-time protection at all, and the
     * SSN is written to the journal and the store in cleartext — after which
     * only post-hoc redaction (with all the gaps in erasure.attack.test.ts) can
     * remove it.
     *
     * REAL-WORLD CONSEQUENCE: the safe default is the one nobody opts into.
     * Every leak documented in erasure.attack.test.ts only exists because the
     * value reached disk in the first place.
     *
     * WHAT SHOULD HAPPEN: default to the conservative built-in patterns and
     * require an explicit opt-OUT, given the patterns are documented as
     * favouring precision over recall.
     */
    const rec = startRecording({ name: 'default agent', dir: home, id: 'nodefault' });
    rec.step({ type: 'user_input', label: 'lookup', input: { ssn: '123-45-6789' } });
    await rec.end();
    expect(readFileSync(dbFile(), 'latin1')).toContain('123-45-6789'); // <-- pinning the hole
  });

  it('a memory-only recording (dir: null) writes nothing to disk at all', async () => {
    const rec = startRecording({ name: 'ephemeral', dir: null, id: 'mem' });
    rec.step({ type: 'user_input', label: 'a', input: { ssn: '123-45-6789' } });
    const run = await rec.end();
    expect(verifyRun(run).ok).toBe(true);
    expect(existsSync(join(home, 'journal'))).toBe(false);
    expect(existsSync(dbFile())).toBe(false);
  });

  it('the journal is written BEFORE step() returns, so a crash cannot lose it', () => {
    // The crash-safety claim, checked at the filesystem rather than trusted.
    const rec = startRecording({ name: 'agent', dir: home, id: 'crashsafe' });
    rec.step({ type: 'user_input', label: 'a' });
    expect(readFileSync(journalFile('crashsafe'), 'utf8').split('\n').filter(Boolean)).toHaveLength(
      2, // meta + one step, already on disk
    );
    rec.step({ type: 'user_input', label: 'b' });
    expect(readFileSync(journalFile('crashsafe'), 'utf8').split('\n').filter(Boolean)).toHaveLength(
      3,
    );
  });
});
