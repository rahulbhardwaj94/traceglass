import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  utimesSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RunStore, parsePolicy, verifyRunFull } from '@traceglass/core';
import { sweepSessions } from './watch.js';
import { generateKeys } from './keys.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');

let home: string;
let sessionsDir: string;
let store: RunStore;
let savedHome: string | undefined;

function seedSession(name = 'sess-fixture.jsonl'): string {
  const projectDir = join(sessionsDir, '-tmp-watch-project');
  mkdirSync(projectDir, { recursive: true });
  const file = join(projectDir, name);
  copyFileSync(join(fixturesDir, 'sample-claude-code-session.jsonl'), file);
  // Age the file so the default settle window is already met.
  const old = new Date(Date.now() - 60_000);
  utimesSync(file, old, old);
  return file;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-watch-home-'));
  sessionsDir = mkdtempSync(join(tmpdir(), 'tg-watch-sess-'));
  savedHome = process.env.TRACEGLASS_HOME;
  process.env.TRACEGLASS_HOME = home;
  store = new RunStore(join(home, 'traceglass.sqlite'));
});

afterEach(() => {
  store.close();
  if (savedHome === undefined) delete process.env.TRACEGLASS_HOME;
  else process.env.TRACEGLASS_HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
  rmSync(sessionsDir, { recursive: true, force: true });
});

describe('sweepSessions', () => {
  it('ingests a settled session once, signed when keys exist, and is idempotent', async () => {
    generateKeys();
    seedSession();

    const first = await sweepSessions(store, { dir: sessionsDir, settleMs: 10_000 });
    expect(first.ingested).toHaveLength(1);
    expect(first.ingested[0]!.runId).toBe('cc-sess-abc'); // predicted from content, not filename
    expect(first.ingested[0]!.signed).toBe(true);

    const stored = store.getRun('cc-sess-abc')!;
    expect(verifyRunFull(stored).ok).toBe(true);

    const second = await sweepSessions(store, { dir: sessionsDir, settleMs: 10_000 });
    expect(second.ingested).toHaveLength(0);
    expect(second.skipped).toBeGreaterThan(0);
  });

  it('leaves a still-active session alone until it settles', async () => {
    const file = seedSession();
    const now = new Date();
    utimesSync(file, now, now); // freshly modified — still being written
    const result = await sweepSessions(store, { dir: sessionsDir, settleMs: 60_000 });
    expect(result.ingested).toHaveLength(0);
    expect(result.skipped).toBe(1);
    expect(store.getRun('cc-sess-abc')).toBeNull();
  });

  it('policy violations are counted, audit-logged, and anchors are written', async () => {
    seedSession();
    // The fixture session retries get_payment_status — forbid that tool.
    const policy = parsePolicy({
      name: 'no payment tools',
      rules: { forbidTools: ['get_payment_status'], requireSignature: true },
    });
    const result = await sweepSessions(store, {
      dir: sessionsDir,
      settleMs: 10_000,
      policy,
      anchor: true,
    });
    expect(result.ingested).toHaveLength(1);
    expect(result.violations).toBeGreaterThanOrEqual(2); // forbidTools + requireSignature (no keys)
    expect(result.ingested[0]!.policy!.ok).toBe(false);

    const audit = readFileSync(join(home, 'audit.jsonl'), 'utf8').trim().split('\n');
    const entry = JSON.parse(audit[0]!) as { reason: string; runId: string };
    expect(entry.reason).toBe('policy-violation');
    expect(entry.runId).toBe('cc-sess-abc');

    expect(existsSync(join(home, 'anchors.jsonl'))).toBe(true);
    const anchor = JSON.parse(readFileSync(join(home, 'anchors.jsonl'), 'utf8').trim()) as {
      runId: string;
    };
    expect(anchor.runId).toBe('cc-sess-abc');
  });

  it('an empty or missing sessions dir sweeps to zero, not an error', async () => {
    const result = await sweepSessions(store, {
      dir: join(sessionsDir, 'does-not-exist'),
      settleMs: 0,
    });
    expect(result).toEqual({ ingested: [], skipped: 0, violations: 0 });
  });
});
