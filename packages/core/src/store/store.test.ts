import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ingestNative } from '../ingest/index.js';
import { finalizeRun } from '../pipeline.js';
import { RunStore } from './store.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const load = (name: string): unknown => JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));

const run = finalizeRun(ingestNative(load('sample-run-native.json')));

describe('RunStore (acceptance §M2)', () => {
  let store: RunStore;
  beforeEach(() => {
    store = new RunStore(':memory:');
  });
  afterEach(() => {
    store.close();
  });

  it('round-trips save -> get preserving the run exactly', () => {
    store.saveRun(run);
    const loaded = store.getRun(run.id);
    expect(loaded).toEqual(run);
  });

  it('lists ingested runs with summary metadata', () => {
    store.saveRun(run);
    const list = store.listRuns();
    expect(list).toHaveLength(1);
    expect(list[0]!.id).toBe(run.id);
    expect(list[0]!.runHash).toBe(run.runHash);
    expect(list[0]!.steps).toBe(run.totals.steps);
  });

  it('is append-only: re-saving the same id throws', () => {
    store.saveRun(run);
    expect(() => store.saveRun(run)).toThrow(/append-only/);
  });

  it('returns null for an unknown id', () => {
    expect(store.getRun('nope')).toBeNull();
  });

  it('searchRuns finds steps by payload text with run + step context (v0.4)', () => {
    store.saveRun(run);
    const loopRun = finalizeRun(ingestNative(load('sample-run-loop.json')));
    store.saveRun(loopRun);

    const hits = store.searchRuns('4471');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.runId === loopRun.id)).toBe(true); // only the collections run mentions 4471
    expect(hits[0]!.snippet.toLowerCase()).toContain('4471');
    expect(hits[0]!.stepIndex).toBeGreaterThanOrEqual(0);

    // Case-insensitive; misses return empty, not errors.
    expect(store.searchRuns('COLLECTIONS').length).toBeGreaterThan(0);
    expect(store.searchRuns('zz-no-such-text-zz')).toEqual([]);

    // LIKE metacharacters are literals: '4_71' must NOT wildcard-match '4471'.
    expect(store.searchRuns('4_71')).toEqual([]);

    // Limit caps results.
    expect(store.searchRuns('a', { limit: 3 }).length).toBeLessThanOrEqual(3);
  });

  it('replaceRedacted overwrites in place and refuses unknown ids (v0.6)', () => {
    store.saveRun(run);
    const redacted = { ...run, name: 'redacted copy' };
    store.replaceRedacted(redacted);
    expect(store.getRun(run.id)!.name).toBe('redacted copy');
    expect(store.listRuns()).toHaveLength(1); // in place, not an extra row
    expect(() => store.replaceRedacted({ ...run, id: 'ghost' })).toThrow(/no such run/);
  });

  it('pruneOlderThan deletes only runs ingested before the cutoff and reports them', () => {
    store.saveRun(run);
    store.saveRun({ ...run, id: 'old-run' });
    // Backdate one row directly (tests only — there is no app-level update path).
    (
      store as unknown as {
        db: { prepare: (sql: string) => { run: (...a: unknown[]) => unknown } };
      }
    ).db
      .prepare(`UPDATE runs SET ingested_at = ? WHERE id = ?`)
      .run('2000-01-01T00:00:00.000Z', 'old-run');

    const pruned = store.pruneOlderThan('2020-01-01T00:00:00.000Z');
    expect(pruned.map((p) => p.id)).toEqual(['old-run']);
    expect(pruned[0]!.runHash).toBe(run.runHash);
    expect(store.getRun('old-run')).toBeNull();
    expect(store.getRun(run.id)).not.toBeNull();
  });
});

/**
 * Erasure has to hold against the file, not just against a SELECT. SQLite
 * leaves a superseded row readable in a freed page, so before secure_delete +
 * VACUUM a "redacted" value came straight back out of the .sqlite via `strings`.
 */
describe('RunStore erasure is durable on disk (v0.7.1)', () => {
  const SECRET = 'chase-account-4471-SECRET';
  let dir: string;
  let dbPath: string;
  let store: RunStore;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'tg-store-erase-'));
    dbPath = join(dir, 'traceglass.sqlite');
    store = new RunStore(dbPath);
  });
  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  /** Raw bytes of the db plus any WAL sidecar — what an attacker would grep. */
  const onDisk = (): string =>
    ['', '-wal', '-shm']
      .map((suffix) => {
        try {
          return readFileSync(dbPath + suffix, 'latin1');
        } catch {
          return '';
        }
      })
      .join('');

  const withSecret = (id: string) => {
    const steps = run.steps.map((s, i) => (i === 0 ? { ...s, input: SECRET } : s));
    return { ...run, id, steps };
  };

  it('a redacted value is not recoverable from the database file', () => {
    store.saveRun(withSecret('redact-me'));
    expect(onDisk()).toContain(SECRET); // precondition: it really was written

    const scrubbed = store.getRun('redact-me')!;
    store.replaceRedacted({
      ...scrubbed,
      steps: scrubbed.steps.map((s, i) =>
        i === 0 ? { ...s, input: '[traceglass:redacted]' } : s,
      ),
    });

    expect(store.getRun('redact-me')!.steps[0]!.input).toBe('[traceglass:redacted]');
    expect(onDisk()).not.toContain(SECRET);
  });

  it('a pruned run leaves no readable remains either', () => {
    store.saveRun(withSecret('prune-me'));
    expect(onDisk()).toContain(SECRET);

    expect(store.pruneOlderThan(new Date(Date.now() + 60_000).toISOString())).toHaveLength(1);
    expect(store.getRun('prune-me')).toBeNull();
    expect(onDisk()).not.toContain(SECRET);
  });
});
