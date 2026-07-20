import { readFileSync } from 'node:fs';
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
