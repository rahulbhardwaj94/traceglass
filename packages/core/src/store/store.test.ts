import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ingestNative } from '../ingest/index.js';
import { finalizeRun } from '../pipeline.js';
import { RunStore } from './store.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const load = (name: string): unknown =>
  JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));

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
});
