import { describe, expect, it } from 'vitest';
import type { Run, Step } from '../model.js';
import { applyHashChain, hashStep } from '../integrity/hash.js';
import { verifyRun } from '../integrity/verify.js';
import { analyzeRun } from '../analyze/index.js';
import { REDACTED_MARKER, verifyCommitments } from './commit.js';
import {
  DEFAULT_PATTERNS,
  RedactionError,
  findPatternPaths,
  patternsByName,
  redactLegacyRun,
  redactRun,
  redactStep,
  scrubStepPayload,
  withCommitments,
} from './redact.js';

function committedStep(index: number, payload: Record<string, unknown>): Step {
  const base = {
    id: `r:${index}`,
    runId: 'r',
    index,
    type: 'tool_call' as const,
    label: `step ${index}`,
    startedAt: `2026-01-01T00:00:0${index}.000Z`,
    durationMs: 10,
    tokens: 1,
    cost: 1,
    toolName: 'db',
    spanId: `s${index}`,
    hash: '',
    prevHash: '',
    ...payload,
  };
  return withCommitments(base) as Step;
}

function makeRun(steps: Step[]): Run {
  return applyHashChain(
    analyzeRun({
      id: 'r',
      name: 'redaction run',
      startedAt: steps[0]!.startedAt,
      endedAt: steps[steps.length - 1]!.startedAt,
      status: 'completed',
      currency: 'USD',
      totals: { tokens: steps.length, cost: steps.length, durationMs: 10, steps: steps.length },
      warnings: [],
      steps,
      runHash: '',
    }),
  );
}

describe('post-hoc redaction preserves integrity', () => {
  it('redacting a leaf does NOT change the step hash or break the chain', () => {
    const run = makeRun([
      committedStep(0, { input: { ssn: '123-45-6789', account: '4471' } }),
      committedStep(1, { output: { ok: true } }),
    ]);
    expect(verifyRun(run).ok).toBe(true);
    const beforeHash = run.steps[0]!.hash;
    const beforeRunHash = run.runHash;

    const { run: redacted, redacted: paths } = redactRun(run, {
      paths: ['r:0#input.ssn'],
      reason: 'GDPR erasure request',
    });

    expect(paths).toEqual(['r:0#input.ssn']);
    // The crux: hash and anchor are untouched...
    expect(redacted.steps[0]!.hash).toBe(beforeHash);
    expect(redacted.runHash).toBe(beforeRunHash);
    // ...so the chain still verifies.
    expect(verifyRun(redacted).ok).toBe(true);
    // The value is genuinely gone, the sibling survives.
    expect((redacted.steps[0]!.input as { ssn: string }).ssn).toBe(REDACTED_MARKER);
    expect((redacted.steps[0]!.input as { account: string }).account).toBe('4471');
    // And the salt was destroyed.
    expect(redacted.steps[0]!.salts!['input.ssn']).toBeUndefined();
    expect(redacted.steps[0]!.commitments!['input.ssn']).toBeDefined(); // commitment survives
  });

  it('records an audit trail of what was removed and why', () => {
    const run = makeRun([committedStep(0, { input: { ssn: '123-45-6789' } })]);
    const { run: redacted } = redactRun(run, {
      paths: ['input.ssn'],
      reason: 'GDPR erasure request',
    });
    const rec = redacted.steps[0]!.redactions!;
    expect(rec).toHaveLength(1);
    expect(rec[0]!.path).toBe('input.ssn');
    expect(rec[0]!.reason).toBe('GDPR erasure request');
    expect(rec[0]!.by).toBe('manual');
  });

  it('a redacted leaf reads as redacted, and siblings stay verifiable', () => {
    const run = makeRun([committedStep(0, { input: { ssn: '123-45-6789', keep: 'visible' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });
    const s = redacted.steps[0]!;
    const check = verifyCommitments(s, s.commitments!, s.salts!);
    expect(check.ok).toBe(true);
    expect(check.redacted).toEqual(['input.ssn']);
    expect(check.verified).toContain('input.keep');
  });

  it('tampering with a VISIBLE leaf after redaction is still caught', () => {
    const run = makeRun([committedStep(0, { input: { ssn: '123-45-6789', keep: 'visible' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });
    const s = redacted.steps[0]!;
    const tampered = { ...s, input: { ssn: REDACTED_MARKER, keep: 'ALTERED' } };
    const check = verifyCommitments(tampered, s.commitments!, s.salts!);
    expect(check.ok).toBe(false);
    expect(check.mismatched).toEqual(['input.keep']);
  });

  it('refuses to redact a pre-0.6 step with no commitments, naming the legacy path', () => {
    const legacy: Step = {
      id: 'r:0',
      runId: 'r',
      index: 0,
      type: 'tool_call',
      label: 'legacy',
      startedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 1,
      tokens: 0,
      cost: 0,
      input: { ssn: '123-45-6789' },
      spanId: 's0',
      hash: '',
      prevHash: '',
    };
    expect(() => redactStep(legacy, 'input.ssn')).toThrow(RedactionError);
    expect(() => redactStep(legacy, 'input.ssn')).toThrow(/legacy path/);
  });

  it('rejects a path that was never committed', () => {
    const step = committedStep(0, { input: { a: 1 } });
    expect(() => redactStep(step, 'input.nope')).toThrow(/no committed leaf/);
  });
});

describe('legacy retrofit (pre-0.6 records)', () => {
  function legacyRun(): Run {
    const step: Step = {
      id: 'r:0',
      runId: 'r',
      index: 0,
      type: 'tool_call',
      label: 'legacy',
      startedAt: '2026-01-01T00:00:00.000Z',
      durationMs: 1,
      tokens: 0,
      cost: 0,
      input: { ssn: '123-45-6789', keep: 'x' },
      spanId: 's0',
      hash: '',
      prevHash: '',
    };
    return makeRun([step]);
  }

  it('redacts by re-chaining, producing a NEW anchor (the weaker guarantee)', () => {
    const run = legacyRun();
    expect(verifyRun(run).ok).toBe(true);
    const before = run.runHash;

    const result = redactLegacyRun(run, { paths: ['input.ssn'], reason: 'erasure' });
    expect(result.redacted).toEqual(['r:0#input.ssn']);
    expect(result.previousRunHash).toBe(before);
    // The anchor MOVED — that is the documented cost of the legacy path.
    expect(result.run.runHash).not.toBe(before);
    // But the new chain is internally consistent.
    expect(verifyRun(result.run).ok).toBe(true);
    expect((result.run.steps[0]!.input as { ssn: string }).ssn).toBe(REDACTED_MARKER);
    expect((result.run.steps[0]!.input as { keep: string }).keep).toBe('x');
    expect(result.run.steps[0]!.redactions![0]!.path).toBe('input.ssn');
  });

  it('drops the old signature, which no longer covers the new anchor', () => {
    const run = { ...legacyRun(), signature: undefined };
    const result = redactLegacyRun(run, { paths: ['input.ssn'] });
    expect(result.run.signature).toBeUndefined();
  });
});

describe('pattern redaction', () => {
  it('detects committed leaves matching built-in patterns', () => {
    const step = committedStep(0, {
      input: { email: 'jane@example.com', ssn: '123-45-6789', safe: 'hello' },
    });
    const paths = findPatternPaths(step, patternsByName(['email', 'ssn'])).sort();
    expect(paths).toEqual(['input.email', 'input.ssn']);
  });

  it('redacts by pattern across a run while keeping the chain intact', () => {
    const run = makeRun([
      committedStep(0, { input: { email: 'jane@example.com', keep: 'x' } }),
      committedStep(1, { output: { note: 'no pii here' } }),
    ]);
    const before = run.runHash;
    const { run: redacted, redacted: paths } = redactRun(run, {
      patterns: patternsByName(['email']),
    });
    expect(paths).toEqual(['r:0#input.email']);
    expect(redacted.runHash).toBe(before);
    expect(verifyRun(redacted).ok).toBe(true);
    expect((redacted.steps[0]!.input as { email: string }).email).toBe(REDACTED_MARKER);
    expect(redacted.steps[1]!.output).toEqual({ note: 'no pii here' }); // untouched
  });

  it('capture-time scrubbing removes the value before it is ever committed', () => {
    const { payload, redactions } = scrubStepPayload(
      { input: { email: 'jane@example.com', keep: 'x' } },
      patternsByName(['email']),
    );
    expect((payload.input as { email: string }).email).toBe(REDACTED_MARKER);
    expect(redactions[0]!.by).toBe('pattern');
    expect(redactions[0]!.reason).toBe('pattern:email');
    // Committing AFTER scrubbing means no commitment to the original exists.
    const committed = withCommitments(payload);
    expect(Object.keys(committed.commitments)).toContain('input.email');
  });

  it('patternsByName rejects an unknown pattern with the available list', () => {
    expect(() => patternsByName(['nope'])).toThrow(/Available: email/);
  });

  it('built-in patterns match representative values', () => {
    const hit = (name: string, v: string) =>
      DEFAULT_PATTERNS.find((p) => p.name === name)!.regex.test(v);
    expect(hit('email', 'a.b+c@example.co.uk')).toBe(true);
    expect(hit('ssn', '123-45-6789')).toBe(true);
    expect(hit('aadhaar', '1234 5678 9012')).toBe(true);
    expect(hit('private-key', '-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    expect(hit('bearer-token', 'sk-abcdefghijklmnop123456')).toBe(true);
    expect(hit('email', 'not an email')).toBe(false);
  });
});

describe('commitments are what make this work', () => {
  it('a committed step hashes over commitments, not raw values', () => {
    const step = committedStep(0, { input: { secret: 'value-a' } });
    // Swapping the raw value WITHOUT updating commitments must not change the
    // hash — the hash never covered the raw value.
    const swapped: Step = { ...step, input: { secret: 'value-b' } };
    expect(hashStep(swapped, '')).toBe(hashStep(step, ''));
    // (Integrity of the raw value is enforced by verifyCommitments instead.)
    const check = verifyCommitments(swapped, step.commitments!, step.salts!);
    expect(check.ok).toBe(false);
    expect(check.mismatched).toEqual(['input.secret']);
  });

  it('SECURITY: verifyRun still catches raw-payload tampering on committed runs', () => {
    // The chain alone cannot see this edit (hash covers commitments), so
    // verifyRun must fall through to the commitment check. Without that,
    // redaction-enabled runs would lose payload tamper-detection entirely.
    const run = makeRun([committedStep(0, { input: { amount: 100 } })]);
    expect(verifyRun(run).ok).toBe(true);

    const tampered: Run = {
      ...run,
      steps: [{ ...run.steps[0]!, input: { amount: 999999 } }],
    };
    // Chain hashes are untouched...
    expect(tampered.steps[0]!.hash).toBe(run.steps[0]!.hash);
    // ...but verification still fails and names the step + the path.
    const result = verifyRun(tampered);
    expect(result.ok).toBe(false);
    expect(result.brokenStepIndex).toBe(0);
    expect(result.message).toContain('input.amount');
  });

  it('a legitimately redacted run still passes verifyRun end to end', () => {
    const run = makeRun([committedStep(0, { input: { ssn: '123-45-6789', keep: 'x' } })]);
    const { run: redacted } = redactRun(run, { paths: ['input.ssn'] });
    expect(verifyRun(redacted).ok).toBe(true);
  });
});
