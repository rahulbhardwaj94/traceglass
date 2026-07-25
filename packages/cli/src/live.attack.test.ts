import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  JOURNAL_FORMAT_VERSION,
  RunStore,
  hashStep,
  journalLine,
  withCommitments,
  type Step,
} from '@traceglass/core';
import { buildServer } from './server.js';

/**
 * ADVERSARIAL SUITE — the live tail API (attack 8, exploited over HTTP).
 *
 * journal.attack.test.ts establishes that `finalizeJournal` refuses poisoned
 * journals while `liveRunFromJournal` verifies nothing. This file proves that
 * gap is reachable from the network: `GET /api/live/:id` reads a journal
 * straight off disk and serves it as evidence, flagged `live: true`, with no
 * integrity check anywhere in the path.
 */

let home: string;
let savedHome: string | undefined;
let store: RunStore;
let app: ReturnType<typeof buildServer>;

const JOURNAL_DIR = () => join(home, 'journal');

beforeAll(async () => {
  home = mkdtempSync(join(tmpdir(), 'tg-live-attack-'));
  savedHome = process.env.TRACEGLASS_HOME;
  process.env.TRACEGLASS_HOME = home;
  mkdirSync(JOURNAL_DIR(), { recursive: true });
  store = new RunStore(':memory:');
  app = buildServer(store);
  await app.ready();
});

afterAll(async () => {
  await app.close();
  store.close();
  if (savedHome === undefined) delete process.env.TRACEGLASS_HOME;
  else process.env.TRACEGLASS_HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
});

/** Write a correctly-chained journal, optionally mutated before it hits disk. */
function writeJournal(
  runId: string,
  amounts: number[],
  mutate: (lines: string[]) => string[] = (l) => l,
): void {
  const lines = [
    journalLine({
      kind: 'meta',
      formatVersion: JOURNAL_FORMAT_VERSION,
      id: runId,
      name: 'in-flight agent',
      currency: 'USD',
      startedAt: '2026-01-01T00:00:00.000Z',
    }),
  ];
  let prevHash = '';
  amounts.forEach((amount, index) => {
    const step = withCommitments({
      id: `${runId}:${index}`,
      runId,
      index,
      type: 'tool_call' as const,
      label: `transfer ${amount}`,
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
    step.hash = hashStep(step, prevHash);
    prevHash = step.hash;
    lines.push(journalLine({ kind: 'step', step }));
  });
  writeFileSync(join(JOURNAL_DIR(), `${runId}.jsonl`), mutate(lines).join(''));
}

describe('ATTACK 8 (over HTTP): the live tail serves unverified journals', () => {
  it('an honest in-flight recording is served as live (baseline)', async () => {
    writeJournal('honest-live', [10, 20]);
    const res = await app.inject({ method: 'GET', url: '/api/live/honest-live' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { live: boolean; status: string; steps: unknown[] };
    expect(body.live).toBe(true);
    expect(body.status).toBe('running');
    expect(body.steps).toHaveLength(2);
  });

  it('VULNERABILITY: a journal with an edited payload is served over the API verbatim', async () => {
    /*
     * VULNERABILITY: GET /api/live/:id calls liveRunFromJournal, which never
     * runs verifyRun. The chain in the journal IS sealed up to the latest step
     * — it is fully checkable — but nothing checks it.
     *
     * REPRODUCTION:
     *   1. echo the journal for an in-flight run out of ~/.traceglass/journal/
     *   2. sed -i 's/"amount":500000/"amount":1/' that file
     *   3. curl localhost:PORT/api/live/<runId>
     *   -> 200, `"live": true`, and the doctored amount.
     * Run `traceglass recover` on the identical bytes seconds later and it is
     * REFUSED with "does not match its commitment".
     *
     * REAL-WORLD CONSEQUENCE: the live dashboard is what an operator watches
     * during an incident — precisely when the record most needs to be
     * trustworthy, and precisely when an agent under attack is still running
     * and its journal still writable. The product enforces integrity on the
     * cold path and drops it on the hot one, with no visible difference.
     *
     * WHAT SHOULD HAPPEN: verify the chain up to the latest step and either
     * refuse (503/409) or return an explicit `verified: false` the dashboard
     * renders as a warning.
     */
    writeJournal('poisoned-live', [500000], (lines) =>
      lines.map((l) => l.replace('"amount":500000', '"amount":1')),
    );

    const res = await app.inject({ method: 'GET', url: '/api/live/poisoned-live' });
    expect(res.statusCode).toBe(200); // <-- THE HOLE
    const body = res.json() as { live: boolean; steps: Array<{ input: { amount: number } }> };
    expect(body.live).toBe(true);
    expect(body.steps[0]!.input.amount).toBe(1); // the lie, served as evidence
    // No field in the response can even express that this is unverified.
    expect(Object.keys(body)).not.toContain('verified');
    expect(Object.keys(body)).not.toContain('integrity');
  });

  it('VULNERABILITY: reordered steps are served in the attacker’s order', async () => {
    writeJournal('reordered-live', [10, 20, 30], (lines) => [
      lines[0]!,
      lines[3]!,
      lines[1]!,
      lines[2]!,
    ]);
    const res = await app.inject({ method: 'GET', url: '/api/live/reordered-live' });
    expect(res.statusCode).toBe(200); // <-- THE HOLE
    const body = res.json() as { steps: Array<{ label: string }> };
    expect(body.steps.map((s) => s.label)).toEqual([
      'transfer 30',
      'transfer 10',
      'transfer 20',
    ]);
  });

  it('VULNERABILITY: a wholly fabricated run appears in GET /api/live', async () => {
    /*
     * VULNERABILITY: discovery only requires that the file parses. Dropping a
     * fabricated journal into ~/.traceglass/journal/ makes a run that never
     * happened appear in the operator's live view as though it were happening
     * right now.
     */
    writeJournal('ghost-run', [1], (lines) =>
      lines.map((l) => l.replace(/"hash":"[0-9a-f]{64}"/, `"hash":"${'de'.repeat(32)}"`)),
    );
    const list = await app.inject({ method: 'GET', url: '/api/live' });
    expect(list.statusCode).toBe(200);
    const listed = list.json() as Array<{ runId: string }>;
    expect(listed.map((r) => r.runId)).toContain('ghost-run'); // <-- THE HOLE

    const detail = await app.inject({ method: 'GET', url: '/api/live/ghost-run' });
    expect(detail.statusCode).toBe(200);
    expect((detail.json() as { live: boolean }).live).toBe(true);
  });

  it('a live run has no anchor, which is the one honest signal in the response', async () => {
    // Not a defence against the above, but worth pinning: `runHash` is empty
    // and status is `running`, so a live payload at least cannot masquerade as
    // a sealed, anchored record.
    writeJournal('unanchored', [10]);
    const body = (await app.inject({ method: 'GET', url: '/api/live/unanchored' })).json() as {
      runHash: string;
      status: string;
    };
    expect(body.runHash).toBe('');
    expect(body.status).toBe('running');
  });

  it('a live id that is neither journaled nor stored still 404s', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/live/no-such-run' });
    expect(res.statusCode).toBe(404);
  });

  it('path traversal in the live id cannot read an arbitrary file', async () => {
    // findLiveRecording matches on the run id INSIDE the journal, not on the
    // filename, so the id is never used to build a path. Pinning that.
    for (const id of [
      '../../etc/passwd',
      '..%2f..%2fetc%2fpasswd',
      '/etc/passwd',
      'honest-live/../../../etc/passwd',
    ]) {
      const res = await app.inject({ method: 'GET', url: `/api/live/${encodeURIComponent(id)}` });
      expect(res.statusCode).toBe(404);
      expect(res.body).not.toContain('root:');
    }
  });
});
