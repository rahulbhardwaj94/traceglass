import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ingestNative } from '../ingest/index.js';
import { finalizeRun } from '../pipeline.js';
import { applyHashChain, canonicalize, computeRunHash } from './hash.js';
import { verifyRun } from './verify.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../../fixtures');
const load = (name: string): unknown => JSON.parse(readFileSync(join(fixturesDir, name), 'utf8'));

const run = finalizeRun(ingestNative(load('sample-run-native.json')));

describe('canonicalize', () => {
  it('is stable regardless of key order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });
  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });
});

describe('hash chain', () => {
  it('step 0 has empty prevHash; each links to the previous hash', () => {
    expect(run.steps[0]!.prevHash).toBe('');
    for (let i = 1; i < run.steps.length; i++) {
      expect(run.steps[i]!.prevHash).toBe(run.steps[i - 1]!.hash);
    }
  });
  it('a tgcanon/1 run anchors on the final step hash', () => {
    const v1 = applyHashChain(ingestNative(load('sample-run-native.json')), { hashVersion: 1 });
    expect(v1.hashVersion).toBeUndefined(); // version 1 is the ABSENCE of the field
    expect(v1.runHash).toBe(v1.steps[v1.steps.length - 1]!.hash);
  });
  it('a tgcanon/2 run anchors on a header hash that covers the chain and the metadata', () => {
    // The anchor is no longer the last step hash: it is a hash OVER the chain
    // anchor plus the run header, which is what puts currency/status/totals
    // inside the sealed material (SPEC §6.2 was the hole).
    expect(run.hashVersion).toBe(2);
    expect(run.runHash).not.toBe(run.steps[run.steps.length - 1]!.hash);
    expect(run.runHash).toMatch(/^[0-9a-f]{64}$/);
    expect(computeRunHash(run)).toBe(run.runHash);
  });
  it('hashes are deterministic', () => {
    const again = applyHashChain(ingestNative(load('sample-run-native.json')));
    expect(again.runHash).toBe(run.runHash);
  });
});

describe('verifyRun (acceptance §M2)', () => {
  it('returns intact for an unmodified run', () => {
    const result = verifyRun(run);
    expect(result.ok).toBe(true);
    expect(result.brokenStepIndex).toBeNull();
  });

  it('reports the correct first-broken step after tampering with a payload', () => {
    // Mutate step #2's dataPayload (e.g. hiding which customer record was read)
    // WITHOUT recomputing hashes, as a tamperer would.
    const tampered = structuredClone(run);
    tampered.steps[2]!.dataPayload = { applicantId: '0000', name: 'REDACTED' };

    const result = verifyRun(tampered);
    expect(result.ok).toBe(false);
    expect(result.brokenStepIndex).toBe(2);
    expect(result.brokenStepId).toBe(tampered.steps[2]!.id);
  });

  it('detects an altered run anchor even if steps are internally consistent', () => {
    const tampered = structuredClone(run);
    tampered.runHash = 'deadbeef';
    const result = verifyRun(tampered);
    expect(result.ok).toBe(false);
  });
});
