import { describe, expect, it } from 'vitest';
import type { Run, Step, StepType } from '../model.js';
import { applyHashChain } from '../integrity/hash.js';
import { analyzeRun } from '../analyze/index.js';
import { withCommitments, redactRun, redactLegacyRun } from '../redact/redact.js';
import { REDACTED_MARKER } from '../redact/commit.js';
import { alignSteps, diffRuns, stepIdentity } from './index.js';

/* ── fixtures ──────────────────────────────────────────────────────────────── */

function step(index: number, type: StepType, over: Partial<Step> = {}): Step {
  return {
    id: `s${index}`,
    runId: 'r',
    index,
    type,
    label: over.label ?? `${type} ${index}`,
    startedAt: `2026-01-01T00:00:0${index}.000Z`,
    durationMs: 100,
    tokens: 10,
    cost: 1,
    spanId: `sp${index}`,
    hash: '',
    prevHash: '',
    ...over,
  };
}

/** Renumber a hand-written step list so `index`/`id` stay consistent. */
function sequence(steps: Step[], runId: string): Step[] {
  return steps.map((s, i) => ({ ...s, index: i, runId, id: `${runId}:${i}` }));
}

function rawRun(id: string, steps: Step[], over: Partial<Run> = {}): Run {
  return analyzeRun({
    id,
    name: 'diff test run',
    startedAt: '2026-01-01T00:00:00.000Z',
    endedAt: '2026-01-01T00:01:00.000Z',
    status: 'completed',
    currency: 'USD',
    totals: { tokens: 0, cost: 0, durationMs: 0, steps: 0 },
    warnings: [],
    steps: sequence(steps, id),
    runHash: '',
    ...over,
  });
}

/** A current-format record (`tgcanon/2`). */
function makeRun(id: string, steps: Step[], over: Partial<Run> = {}): Run {
  return applyHashChain(rawRun(id, steps, over));
}

/** A record in the legacy format, which declares no version at all. */
function makeLegacyRun(id: string, steps: Step[], over: Partial<Run> = {}): Run {
  return applyHashChain(rawRun(id, steps, over), { hashVersion: 1 });
}

const baseSteps = (): Step[] => [
  step(0, 'user_input', { label: 'Dun account 4471', input: { account: '4471' } }),
  step(1, 'tool_call', {
    label: 'Tool: get_payment_status',
    toolName: 'get_payment_status',
    output: { status: 'overdue' },
    tokens: 800,
    cost: 0.4,
  }),
  step(2, 'final_output', { label: 'Done', output: 'Reminder sent.' }),
];

/* ── identity and alignment ────────────────────────────────────────────────── */

describe('step identity', () => {
  it('is type + tool name, and deliberately excludes the label and payload', () => {
    const a = step(0, 'tool_call', { toolName: 'db_query', label: 'Tool: db_query' });
    const b = step(7, 'tool_call', {
      toolName: 'db_query',
      label: 'something else entirely',
      input: { q: 'select 1' },
    });
    expect(stepIdentity(a)).toBe(stepIdentity(b));
  });
});

describe('alignSteps', () => {
  it('reports one insertion rather than a cascade of changes', () => {
    const a = sequence(baseSteps(), 'a');
    const b = sequence([step(0, 'plan', { label: 'Think' }), ...baseSteps()], 'b');
    const { entries } = alignSteps(a, b);

    expect(entries.filter((e) => e.a === null)).toHaveLength(1);
    expect(entries.filter((e) => e.b === null)).toHaveLength(0);
    // Every original step still lines up, shifted by one.
    for (const e of entries) {
      if (e.a === null) continue;
      expect(e.b).toBe(e.a + 1);
    }
  });

  it('falls back to positional matching, and says so, when the runs are huge', () => {
    const many = (n: number, offset: number): Step[] =>
      sequence(
        Array.from({ length: n }, (_, i) =>
          step(i, 'tool_call', { toolName: `tool_${(i + offset) % 5}` }),
        ),
        'x',
      );
    const wide = alignSteps(many(30, 0), many(30, 1), { maxMatrixCells: 1 });
    expect(wide.degraded).toBe(true);
  });
});

/* ── the diff ──────────────────────────────────────────────────────────────── */

describe('diffRuns', () => {
  it('reports two identical runs as equivalent, with nothing changed', () => {
    const a = makeRun('a', baseSteps());
    const b = makeRun('b', baseSteps());
    const d = diffRuns(a, b);

    expect(d.equivalent).toBe(true);
    expect(d.fullyComparable).toBe(true);
    expect(d.caveats).toEqual([]);
    expect(d.summary).toEqual({
      same: 3,
      changed: 0,
      added: 0,
      removed: 0,
      moved: 0,
      incomparableLeaves: 0,
    });
    expect(d.totals.cost.delta).toBe(0);
    expect(d.steps.every((s) => s.kind === 'same')).toBe(true);
  });

  it('reports an inserted step as an insertion, not a cascade', () => {
    const a = makeRun('a', baseSteps());
    const b = makeRun('b', [step(0, 'plan', { label: 'Think first' }), ...baseSteps()]);
    const d = diffRuns(a, b);

    expect(d.summary.added).toBe(1);
    expect(d.summary.removed).toBe(0);
    expect(d.summary.changed).toBe(0);
    expect(d.summary.same).toBe(3);

    const added = d.steps.find((s) => s.kind === 'added');
    expect(added?.type).toBe('plan');
    expect(added?.aIndex).toBeNull();
    expect(added?.bIndex).toBe(0);
    expect(added?.cost.delta).toBe(1);
  });

  it('reports a deleted step as a deletion', () => {
    const full = baseSteps();
    const a = makeRun('a', full);
    const b = makeRun('b', [full[0]!, full[2]!]);
    const d = diffRuns(a, b);

    expect(d.summary.removed).toBe(1);
    expect(d.summary.added).toBe(0);
    const removed = d.steps.find((s) => s.kind === 'removed');
    expect(removed?.toolName).toBe('get_payment_status');
    expect(removed?.cost.delta).toBe(-0.4);
    expect(removed?.tokens.delta).toBe(-800);
  });

  it('locates a changed payload precisely, leaving every other step alone', () => {
    const changed = baseSteps();
    changed[0] = step(0, 'user_input', {
      label: 'Dun account 4471',
      input: { account: '4472' },
    });
    const d = diffRuns(makeRun('a', baseSteps()), makeRun('b', changed));

    expect(d.equivalent).toBe(false);
    expect(d.summary.changed).toBe(1);
    expect(d.summary.same).toBe(2);
    expect(d.summary.added + d.summary.removed).toBe(0);

    const hit = d.steps.find((s) => s.kind === 'changed');
    expect(hit?.leaves).toEqual([
      { path: 'input.account', status: 'changed', a: '4471', b: '4472' },
    ]);
  });

  it('finds a leaf nested under a dotted key without raising a false alarm', () => {
    // The tgcanon/2 escaping case (SPEC §12.5) — matched on the escaped path.
    const withDotted = (email: string): Step[] => [
      step(0, 'user_input', { label: 'Lookup', input: { 'user.email': email, ok: true } }),
    ];
    const same = diffRuns(makeRun('a', withDotted('x@y.z')), makeRun('b', withDotted('x@y.z')));
    expect(same.equivalent).toBe(true);

    const moved = diffRuns(makeRun('a', withDotted('x@y.z')), makeRun('b', withDotted('q@y.z')));
    expect(moved.steps[0]!.leaves).toEqual([
      { path: 'input.user\\.email', status: 'changed', a: 'x@y.z', b: 'q@y.z' },
    ]);
  });

  it('reports a reordered step as moved, not as a delete plus an insert', () => {
    const order = (first: string, second: string): Step[] => [
      step(0, 'user_input', { label: 'Start' }),
      step(1, 'tool_call', { toolName: first, label: `Tool: ${first}` }),
      step(2, 'tool_call', { toolName: second, label: `Tool: ${second}` }),
      step(3, 'final_output', { label: 'Done' }),
    ];
    const d = diffRuns(makeRun('a', order('alpha', 'beta')), makeRun('b', order('beta', 'alpha')));

    expect(d.summary.added).toBe(0);
    expect(d.summary.removed).toBe(0);
    expect(d.summary.moved).toBe(1);
    expect(d.equivalent).toBe(false);
  });

  it('pairs a swapped tool inside a gap so the change is located, not cascaded', () => {
    const withTool = (tool: string): Step[] => [
      step(0, 'user_input', { label: 'Start' }),
      step(1, 'tool_call', { toolName: tool, label: `Tool: ${tool}` }),
      step(2, 'final_output', { label: 'Done' }),
    ];
    const d = diffRuns(makeRun('a', withTool('search_docs')), makeRun('b', withTool('search_web')));

    expect(d.summary.added).toBe(0);
    expect(d.summary.removed).toBe(0);
    expect(d.summary.changed).toBe(1);
    const hit = d.steps.find((s) => s.kind === 'changed');
    expect(hit?.fields).toEqual([
      { field: 'label', a: 'Tool: search_docs', b: 'Tool: search_web' },
      { field: 'toolName', a: 'search_docs', b: 'search_web' },
    ]);
  });

  it('summarises how tool usage moved', () => {
    const a = makeRun('a', [
      step(0, 'tool_call', { toolName: 'db_query', label: 'Tool: db_query' }),
      step(1, 'tool_call', { toolName: 'db_query', label: 'Tool: db_query' }),
    ]);
    const b = makeRun('b', [
      step(0, 'tool_call', { toolName: 'db_query', label: 'Tool: db_query' }),
      step(1, 'tool_call', { toolName: 'send_email', label: 'Tool: send_email' }),
    ]);
    const d = diffRuns(a, b);

    expect(d.tools).toEqual([
      { toolName: 'db_query', a: 2, b: 1, delta: -1 },
      { toolName: 'send_email', a: 0, b: 1, delta: 1 },
    ]);
  });

  it('reports warnings that appeared and warnings that cleared', () => {
    const loop = (n: number): Step[] => [
      step(0, 'user_input', { label: 'Start' }),
      ...Array.from({ length: n }, (_, i) =>
        step(i + 1, 'tool_call', {
          toolName: 'get_payment_status',
          label: 'Tool: get_payment_status',
        }),
      ),
      step(n + 1, 'final_output', { label: 'Done' }),
    ];
    const clean = makeRun('a', loop(1));
    const looping = makeRun('b', loop(3));

    const appeared = diffRuns(clean, looping);
    expect(appeared.warnings.appeared.map((w) => w.kind)).toContain('loop');
    expect(appeared.warnings.cleared).toEqual([]);

    const cleared = diffRuns(looping, clean);
    expect(cleared.warnings.cleared.map((w) => w.kind)).toContain('loop');
    expect(cleared.warnings.appeared).toEqual([]);
  });

  it('keeps a warning that persists out of appeared and cleared', () => {
    const withError = (): Step[] => [
      step(0, 'user_input', { label: 'Start' }),
      step(1, 'error', { label: 'Boom' }),
    ];
    const d = diffRuns(makeRun('a', withError()), makeRun('b', withError()));
    expect(d.warnings.persisted.map((w) => w.kind)).toEqual(['error']);
    expect(d.warnings.appeared).toEqual([]);
    expect(d.warnings.cleared).toEqual([]);
  });

  it('moves cost and tokens with a signed delta', () => {
    const dearer = baseSteps();
    dearer[1] = step(1, 'tool_call', {
      label: 'Tool: get_payment_status',
      toolName: 'get_payment_status',
      output: { status: 'overdue' },
      tokens: 1600,
      cost: 0.9,
    });
    const d = diffRuns(makeRun('a', baseSteps()), makeRun('b', dearer));

    const hit = d.steps.find((s) => s.kind === 'changed');
    expect(hit?.cost).toEqual({ a: 0.4, b: 0.9, delta: expect.closeTo(0.5, 10) as number });
    expect(hit?.tokens).toEqual({ a: 800, b: 1600, delta: 800 });
    expect(d.totals.tokens.delta).toBe(800);
  });
});

/* ── the honesty rules ─────────────────────────────────────────────────────── */

describe('diffRuns: redaction is not a change', () => {
  const piiSteps = (): Step[] => [
    step(0, 'user_input', {
      label: 'Lookup',
      ...withCommitments({ input: { ssn: '123-45-6789', keep: 'visible' } }, 2),
    }),
  ];

  it('reports a redacted leaf as not comparable, never as changed', () => {
    const original = makeRun('a', piiSteps());
    const { run: redacted, redacted: paths } = redactRun(original, {
      paths: ['input.ssn'],
      reason: 'erasure request',
    });
    expect(paths).toHaveLength(1);
    // The record is genuinely intact: only the value and its salt are gone.
    expect(redacted.runHash).toBe(original.runHash);

    const fresh = makeRun('b', piiSteps());
    const d = diffRuns(redacted, fresh);

    const leaves = d.steps[0]!.leaves;
    expect(leaves).toEqual([
      { path: 'input.ssn', status: 'redacted', redactedOn: 'a', b: '123-45-6789' },
    ]);
    expect(leaves.every((l) => l.status !== 'changed')).toBe(true);

    // Nothing OBSERVABLE differs, and the diff says so without pretending the
    // destroyed value was equal to the surviving one.
    expect(d.summary.changed).toBe(0);
    expect(d.steps[0]!.kind).toBe('same');
    expect(d.equivalent).toBe(true);
    expect(d.fullyComparable).toBe(false);
    expect(d.summary.incomparableLeaves).toBe(1);
    expect(d.caveats.map((c) => c.kind)).toContain('redacted-leaves');
  });

  it('reports a leaf redacted on both sides as not comparable', () => {
    const redact = (id: string): Run =>
      redactRun(makeRun(id, piiSteps()), { paths: ['input.ssn'] }).run;
    const d = diffRuns(redact('a'), redact('b'));

    expect(d.steps[0]!.leaves).toEqual([
      { path: 'input.ssn', status: 'redacted', redactedOn: 'both' },
    ]);
    expect(d.equivalent).toBe(true);
    expect(d.fullyComparable).toBe(false);
  });

  it('recognises a legacy redaction, which carries no commitments at all', () => {
    const legacySteps = (): Step[] => [
      step(0, 'user_input', { label: 'Lookup', input: { ssn: '123-45-6789' } }),
    ];
    const legacy = makeLegacyRun('a', legacySteps());
    const { run: scrubbed } = redactLegacyRun(legacy, { paths: ['input.ssn'] });
    expect(scrubbed.steps[0]!.commitments).toBeUndefined();

    const fresh = makeLegacyRun('b', legacySteps());
    const d = diffRuns(scrubbed, fresh);

    expect(d.steps[0]!.leaves).toEqual([
      { path: 'input.ssn', status: 'redacted', redactedOn: 'a', b: '123-45-6789' },
    ]);
  });

  it('treats the redaction marker itself as destroyed data, not as a value', () => {
    const marked = makeRun('a', [
      step(0, 'user_input', { label: 'Lookup', input: { ssn: REDACTED_MARKER } }),
    ]);
    const fresh = makeRun('b', [
      step(0, 'user_input', { label: 'Lookup', input: { ssn: '123-45-6789' } }),
    ]);
    expect(diffRuns(marked, fresh).steps[0]!.leaves[0]!.status).toBe('redacted');
  });
});

describe('diffRuns: records that cannot be fully compared', () => {
  it('withholds the cost delta when the two runs use different currencies', () => {
    const a = makeRun('a', baseSteps());
    const b = makeRun('b', baseSteps(), { currency: 'INR' });
    const d = diffRuns(a, b);

    expect(d.currency).toEqual({ a: 'USD', b: 'INR', same: false });
    expect(d.totals.cost).toEqual({ a: 2.4, b: 2.4, delta: null });
    expect(d.steps.every((s) => s.cost.delta === null)).toBe(true);
    expect(d.caveats.map((c) => c.kind)).toContain('currency-mismatch');
    expect(d.equivalent).toBe(false);
  });

  it('does not call an equal-but-differently-denominated step unchanged by accident', () => {
    const dearer = baseSteps();
    dearer[1] = step(1, 'tool_call', {
      label: 'Tool: get_payment_status',
      toolName: 'get_payment_status',
      output: { status: 'overdue' },
      tokens: 800,
      cost: 0.9,
    });
    const d = diffRuns(makeRun('a', baseSteps()), makeRun('b', dearer, { currency: 'INR' }));
    const hit = d.steps.find((s) => s.aIndex === 1);
    expect(hit?.kind).toBe('changed');
    expect(hit?.cost).toEqual({ a: 0.4, b: 0.9, delta: null });
  });

  it('flags a comparison across hash versions instead of pretending it is clean', () => {
    const a = makeLegacyRun('a', baseSteps());
    const b = makeRun('b', baseSteps());
    expect(a.hashVersion).toBeUndefined();
    expect(b.hashVersion).toBe(2);

    const d = diffRuns(a, b);
    expect(d.a.hashVersion).toBe(1);
    expect(d.b.hashVersion).toBe(2);
    expect(d.caveats.map((c) => c.kind)).toContain('hash-version-mismatch');
    expect(d.fullyComparable).toBe(false);
    // The steps themselves are still comparable — the caveat is about paths.
    expect(d.summary.changed).toBe(0);
  });

  it('flags a record declaring a hash version this build does not understand', () => {
    const a = makeRun('a', baseSteps());
    const b = { ...makeRun('b', baseSteps()), hashVersion: 99 };
    const d = diffRuns(a, b);
    expect(d.caveats.map((c) => c.kind)).toContain('unsupported-hash-version');
  });

  it('says so when the alignment had to degrade to positional matching', () => {
    const order = (first: string, second: string): Step[] => [
      step(0, 'user_input', { label: 'Start' }),
      step(1, 'tool_call', { toolName: first, label: `Tool: ${first}` }),
      step(2, 'tool_call', { toolName: second, label: `Tool: ${second}` }),
      step(3, 'final_output', { label: 'Done' }),
    ];
    const d = diffRuns(makeRun('a', order('alpha', 'beta')), makeRun('b', order('beta', 'alpha')), {
      maxMatrixCells: 1,
    });
    expect(d.caveats.map((c) => c.kind)).toContain('alignment-degraded');
  });
});
