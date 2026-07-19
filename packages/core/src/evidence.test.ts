import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createEnvelope, parseEvidence } from './evidence.js';
import { ingestAndFinalize } from './pipeline.js';
import { verifyRun } from './integrity/verify.js';
import type { Run } from './model.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
const run = ingestAndFinalize(
  JSON.parse(readFileSync(join(fixturesDir, 'sample-run-native.json'), 'utf8')),
);

describe('evidence envelope', () => {
  it('round-trips: export → parse → verifies', () => {
    const json = JSON.stringify(createEnvelope(run));
    const parsed = parseEvidence(JSON.parse(json));
    expect(parsed.id).toBe(run.id);
    expect(verifyRun(parsed).ok).toBe(true);
  });

  it('accepts a bare Run value without an envelope', () => {
    const parsed = parseEvidence(JSON.parse(JSON.stringify(run)));
    expect(parsed.runHash).toBe(run.runHash);
  });

  it('a tampered step in the envelope fails verification at that step', () => {
    const envelope = JSON.parse(JSON.stringify(createEnvelope(run))) as { run: Run };
    envelope.run.steps[1]!.cost = 99999;
    const parsed = parseEvidence(envelope);
    const result = verifyRun(parsed);
    expect(result.ok).toBe(false);
    expect(result.brokenStepIndex).toBe(1);
  });

  it('rejects an unknown formatVersion with a clear message', () => {
    expect(() => parseEvidence({ formatVersion: 99, run })).toThrow(/format version 99/);
  });
});
