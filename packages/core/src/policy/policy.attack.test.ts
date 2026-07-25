import { describe, expect, it } from 'vitest';
import type { Run, Step, StepType } from '../model.js';
import { analyzeRun } from '../analyze/index.js';
import { applyHashChain } from '../integrity/hash.js';
import { evaluatePolicy, parsePolicy, toolMatches } from './policy.js';

/**
 * ADVERSARIAL SUITE — guardrail policy (attack 5).
 *
 * `forbidTools` and `requireApprovalFor` are the rules an operator writes when
 * they mean "the agent must NEVER do this". These tests ask whether an agent
 * (or whoever controls the tool registry) can get the forbidden call through
 * anyway. Several of them can.
 */

interface StepOpts {
  type?: StepType;
  toolName?: string;
  input?: unknown;
  cost?: number;
}

function step(index: number, o: StepOpts = {}): Step {
  return {
    id: `r:${index}`,
    runId: 'r',
    index,
    type: o.type ?? 'tool_call',
    label: `step ${index}`,
    startedAt: new Date(Date.UTC(2026, 0, 1, 0, 0, index)).toISOString(),
    durationMs: 1,
    tokens: 0,
    cost: o.cost ?? 0,
    ...(o.toolName !== undefined ? { toolName: o.toolName } : {}),
    ...(o.input !== undefined ? { input: o.input } : {}),
    spanId: `span-${index}`,
    hash: '',
    prevHash: '',
  };
}

function makeRun(steps: Step[]): Run {
  return applyHashChain(
    analyzeRun({
      id: 'r',
      name: 'r',
      startedAt: steps[0]!.startedAt,
      endedAt: steps[steps.length - 1]!.startedAt,
      status: 'completed',
      currency: 'USD',
      totals: {
        tokens: 0,
        cost: steps.reduce((a, s) => a + s.cost, 0),
        durationMs: steps.length,
        steps: steps.length,
      },
      warnings: [],
      steps,
      runHash: '',
    }),
  );
}

/** Did `forbidTools: [pattern]` catch a run that called `toolName`? */
function forbidden(toolName: string, pattern: string, type: StepType = 'tool_call'): boolean {
  const run = makeRun([step(0, { type, toolName })]);
  return !evaluatePolicy(run, parsePolicy({ rules: { forbidTools: [pattern] } })).ok;
}

describe('ATTACK 5a: forbidTools string-matching bypasses', () => {
  it('the honest case is caught (so the bypasses below are real)', () => {
    expect(forbidden('payments.refund', 'payments.refund')).toBe(true);
    expect(forbidden('payments.refund', 'payments.*')).toBe(true);
    expect(forbidden('account_delete', '*_delete')).toBe(true);
    expect(forbidden('anything.at.all', '*')).toBe(true);
  });

  it('FIXED (v0.8): case variants no longer walk through forbidTools', () => {
    /*
     * WAS A VULNERABILITY: `toolMatches` was case-SENSITIVE while
     * `forbidInputText` in the same file was case-INSENSITIVE, so an operator
     * who wrote `forbidTools: ["payments.refund"]` did not block
     * `Payments.Refund`. Tool names come from MCP servers, plugin registries
     * and LLM output, none of which guarantee casing, so a rename silently
     * disarmed the guardrail while the check still reported PASS.
     *
     * FIXED by folding both sides through `foldToolName` (NFKC + zero-width
     * strip + trim + lowercase) in policy.ts.
     */
    expect(forbidden('Payments.Refund', 'payments.refund')).toBe(true);
    expect(forbidden('PAYMENTS.REFUND', 'payments.refund')).toBe(true);
    expect(forbidden('Payments.Refund', 'payments.*')).toBe(true);
    expect(forbidden('ACCOUNT_DELETE', '*_delete')).toBe(true);

    // The fold must not make matching sloppy: a genuinely different tool is
    // still allowed.
    expect(forbidden('payments.refunded', 'payments.refund')).toBe(false);
    expect(forbidden('billing.charge', 'payments.*')).toBe(false);

    // forbidInputText was already case-insensitive; the two rules now agree.
    const run = makeRun([step(0, { toolName: 'bash', input: { cmd: 'cat .ENV' } })]);
    expect(evaluatePolicy(run, parsePolicy({ rules: { forbidInputText: ['.env'] } })).ok).toBe(
      false,
    );
  });

  it('FIXED (v0.8): whitespace no longer defeats a rule or a prefix wildcard', () => {
    /*
     * WAS A VULNERABILITY: tool names were never trimmed, so " payments.refund"
     * failed both the exact match and the `payments.*` glob — the name no
     * longer STARTED with "payments.". A single stray space from an LLM, a
     * YAML registry or a copy-paste disabled the rule, with no visible
     * difference in the dashboard (which renders names trimmed).
     *
     * FIXED by trimming both sides in `foldToolName`.
     */
    expect(forbidden(' payments.refund', 'payments.refund')).toBe(true);
    expect(forbidden(' payments.refund', 'payments.*')).toBe(true);
    expect(forbidden('\tpayments.refund', 'payments.*')).toBe(true);
    expect(forbidden('\npayments.refund', 'payments.*')).toBe(true);
    expect(forbidden('payments.refund ', 'payments.refund')).toBe(true);
    expect(forbidden('payments.refund ', 'payments.*')).toBe(true);

    // Whitespace inside the name is still meaningful — only the edges fold.
    expect(forbidden('payments .refund', 'payments.refund')).toBe(false);
  });

  it('PARTIALLY FIXED (v0.8): zero-width chars are folded, homoglyphs are NOT', () => {
    /*
     * Zero-width characters are now stripped and the name is NFKC-normalized,
     * so the invisible-character evasions are closed.
     *
     * VULNERABILITY (STILL OPEN): NFKC does not fold confusable SCRIPTS. A
     * Cyrillic "а" (U+0430) renders identically to Latin "a" in every
     * dashboard, log and report, and normalization leaves it untouched — so
     * "pаyments.refund" still matches nothing.
     *
     * REAL-WORLD CONSEQUENCE: this is the deliberate-evasion case. A malicious
     * or compromised tool registers itself with one Cyrillic letter, the policy
     * reports PASS, and the audit report shows what looks exactly like the
     * forbidden call.
     *
     * WHAT SHOULD HAPPEN: apply a UTS #39 confusable skeleton before matching,
     * and flag any tool name mixing scripts as suspicious in its own right —
     * a legitimate tool has no reason to do it.
     */
    const cyrillicA = 'pаyments.refund'; // "а" is U+0430, not U+0061
    expect(cyrillicA).not.toBe('payments.refund');
    expect(cyrillicA.length).toBe('payments.refund'.length); // visually identical
    expect(forbidden(cyrillicA, 'payments.refund')).toBe(false); // <-- THE HOLE
    expect(forbidden(cyrillicA, 'payments.*')).toBe(false); // <-- THE HOLE

    // Closed in v0.8: zero-width space and stray newlines are folded away.
    expect(forbidden('payments.refund​', 'payments.refund')).toBe(true);
    expect(forbidden('payments.refund\n', 'payments.refund')).toBe(true);
    expect(forbidden('pay​ments.refund', 'payments.refund')).toBe(true);
  });

  it('VULNERABILITY: forbidTools only inspects tool_call steps', () => {
    /*
     * VULNERABILITY: `toolSteps()` filters `s.type === 'tool_call'`. A step
     * carrying a `toolName` under ANY other type (llm_reasoning, branch,
     * final_output, approval) is invisible to forbidTools and
     * requireApprovalFor.
     *
     * REAL-WORLD CONSEQUENCE: the step type is chosen by whatever produced the
     * record — an SDK caller, an ingester, or a mis-mapped OTel span. Recording
     * the forbidden call as `llm_reasoning` with the same toolName renders the
     * guardrail inert while the report still shows the tool was used.
     *
     * WHAT SHOULD HAPPEN: match on the presence of `toolName`, not on the step
     * type — or fail the policy when a non-tool_call step carries a toolName.
     */
    expect(forbidden('payments.refund', 'payments.*', 'tool_call')).toBe(true);
    expect(forbidden('payments.refund', 'payments.*', 'llm_reasoning')).toBe(false); // <-- HOLE
    expect(forbidden('payments.refund', 'payments.*', 'branch')).toBe(false);
    expect(forbidden('payments.refund', 'payments.*', 'final_output')).toBe(false);
  });
});

describe('ATTACK 5b: glob edges', () => {
  it('a bare "*" matches everything, including the empty tool name', () => {
    expect(toolMatches('anything', '*')).toBe(true);
    expect(toolMatches('', '*')).toBe(true);
  });

  it('an empty pattern is rejected by the schema, so it cannot silently match nothing', () => {
    expect(() => parsePolicy({ rules: { forbidTools: [''] } })).toThrow();
    expect(() => parsePolicy({ rules: { requireApprovalFor: [''] } })).toThrow();
    expect(() => parsePolicy({ rules: { forbidInputText: [''] } })).toThrow();
    // Defensive: toolMatches itself would treat '' as an exact match on ''.
    expect(toolMatches('anything', '')).toBe(false);
    expect(toolMatches('', '')).toBe(true);
  });

  it('VULNERABILITY: "**" silently matches almost nothing', () => {
    /*
     * VULNERABILITY: only ONE leading or trailing `*` is supported, but a
     * pattern with two is accepted rather than rejected. `"**"` takes the
     * `startsWith('*')` branch and becomes "endsWith('*')" — i.e. it matches
     * only tool names that literally end in an asterisk.
     *
     * REAL-WORLD CONSEQUENCE: an operator writing `forbidTools: ["**"]`
     * expecting "block everything" gets a rule that blocks nothing, and the
     * check reports PASS. A guardrail that fails OPEN and silent is worse than
     * no guardrail.
     *
     * WHAT SHOULD HAPPEN: reject patterns with more than one wildcard at parse
     * time, so the operator finds out immediately.
     */
    expect(toolMatches('anything', '**')).toBe(false); // <-- THE HOLE
    expect(toolMatches('payments.refund', '**')).toBe(false);
    expect(toolMatches('weird*', '**')).toBe(true); // only literal-asterisk names
    expect(() => parsePolicy({ rules: { forbidTools: ['**'] } })).not.toThrow();
  });

  it('VULNERABILITY: an interior wildcard is treated as a literal', () => {
    /*
     * VULNERABILITY: `"a*b"` has no leading or trailing `*`, so it falls
     * through to exact string equality against the literal name "a*b".
     * Likewise `"*.*"` takes the leading-`*` branch and demands the name END
     * with the literal ".*".
     *
     * REAL-WORLD CONSEQUENCE: `forbidTools: ["payments.*.execute"]` is a
     * natural thing to write and matches nothing at all — silently.
     *
     * WHAT SHOULD HAPPEN: reject interior wildcards at parse time.
     */
    expect(toolMatches('aXXXb', 'a*b')).toBe(false); // <-- THE HOLE
    expect(toolMatches('payments.refund.execute', 'payments.*.execute')).toBe(false);
    expect(toolMatches('payments.refund', '*.*')).toBe(false);
    expect(() => parsePolicy({ rules: { forbidTools: ['payments.*.execute'] } })).not.toThrow();
  });

  it('a trailing-* pattern does not match the prefix itself', () => {
    // "payments.*" matching the bare name "payments" is arguable; pinning the
    // current behaviour so a future change to the matcher is a deliberate one.
    expect(toolMatches('payments', 'payments.*')).toBe(false);
    expect(toolMatches('payments.', 'payments.*')).toBe(true);
  });
});

describe('ATTACK 5c: requireApprovalFor', () => {
  it('the honest cases hold: no approval fails, a preceding approval passes', () => {
    const unapproved = makeRun([step(0, { toolName: 'payments.refund' })]);
    const policy = parsePolicy({ rules: { requireApprovalFor: ['payments.*'] } });
    expect(evaluatePolicy(unapproved, policy).ok).toBe(false);
    expect(evaluatePolicy(unapproved, policy).violations[0]!.rule).toBe('requireApprovalFor');

    const approved = makeRun([
      step(0, { type: 'approval', input: { decision: 'approve' } }),
      step(1, { toolName: 'payments.refund' }),
    ]);
    expect(evaluatePolicy(approved, policy).ok).toBe(true);
  });

  it('an approval AFTER the call does not count', () => {
    const afterTheFact = makeRun([
      step(0, { toolName: 'payments.refund' }),
      step(1, { type: 'approval', input: { decision: 'approve' } }),
    ]);
    expect(
      evaluatePolicy(afterTheFact, parsePolicy({ rules: { requireApprovalFor: ['payments.*'] } }))
        .ok,
    ).toBe(false);
  });

  it('VULNERABILITY: ANY earlier approval satisfies EVERY approval rule', () => {
    /*
     * VULNERABILITY: the check is
     *   run.steps.some(a => a.type === 'approval' && a.index < s.index)
     * — it never looks at WHAT was approved. One approval step anywhere earlier
     * in the run unlocks every requireApprovalFor pattern for the rest of it.
     *
     * REAL-WORLD CONSEQUENCE: this is the classic confused deputy. A human
     * approves something innocuous ("send the customer an email"), and that
     * single click retroactively satisfies the approval gate on
     * payments.refund, account_delete and everything else for the remainder of
     * the run. The compliance report says "approval obtained" and names a
     * decision the approver never made.
     *
     * WHAT SHOULD HAPPEN: the approval step must reference the tool (or the
     * step) it authorizes, and the match must be scoped to that reference.
     */
    const run = makeRun([
      // A human approves sending an email. Nothing about payments.
      step(0, { type: 'approval', input: { for: 'send_email', decision: 'approve' } }),
      step(1, { toolName: 'send_email' }),
      // ...and now the agent refunds half a million with no further sign-off.
      step(2, { toolName: 'payments.refund', input: { amount: 500000 } }),
      step(3, { toolName: 'account_delete' }),
    ]);
    const policy = parsePolicy({
      rules: { requireApprovalFor: ['payments.*', 'account_delete'] },
    });
    const result = evaluatePolicy(run, policy);
    expect(result.ok).toBe(true); // <-- THE HOLE
    expect(result.violations).toEqual([]);

    // The approval never mentioned either tool.
    expect(JSON.stringify(run.steps[0]!.input)).not.toContain('payments');
    expect(JSON.stringify(run.steps[0]!.input)).not.toContain('account_delete');
  });

  it('VULNERABILITY: a DENIED approval satisfies the gate just as well as an approval', () => {
    /*
     * VULNERABILITY: the decision recorded on the approval step is never read.
     * A step of type `approval` whose payload says `decision: "deny"` still
     * satisfies requireApprovalFor.
     *
     * REAL-WORLD CONSEQUENCE: a human explicitly REFUSES the action, the agent
     * proceeds anyway, and the policy check reports PASS — the exact scenario
     * the rule exists to catch.
     *
     * WHAT SHOULD HAPPEN: an approval step must carry a machine-readable
     * decision, and only an affirmative one may satisfy the gate.
     */
    const run = makeRun([
      step(0, { type: 'approval', input: { for: 'payments.refund', decision: 'deny' } }),
      step(1, { toolName: 'payments.refund', input: { amount: 500000 } }),
    ]);
    const result = evaluatePolicy(
      run,
      parsePolicy({ rules: { requireApprovalFor: ['payments.*'] } }),
    );
    expect(result.ok).toBe(true); // <-- THE HOLE
    expect(JSON.stringify(run.steps[0]!.input)).toContain('deny');
  });

  it('the approval gate is steered by step.index, which nothing validates', () => {
    // Chained to the integrity finding that indices are unchecked: the ordering
    // comparison uses `a.index < s.index`, not array position. A recorder that
    // emits a low index on a late approval moves the gate.
    const steps = [
      step(0, { toolName: 'payments.refund' }),
      { ...step(1, { type: 'approval' as StepType }), index: -0 },
    ];
    // An approval claiming index 0 while the call claims index 0 too: not <, so
    // the gate still fails here. Pinning it so a change in the comparison is
    // deliberate.
    const run = makeRun(steps);
    expect(
      evaluatePolicy(run, parsePolicy({ rules: { requireApprovalFor: ['payments.*'] } })).ok,
    ).toBe(false);
  });
});

describe('ATTACK 5d: rules that DO hold', () => {
  it('numeric limits are exact and cannot be nudged past by rounding', () => {
    const run = makeRun([step(0, { cost: 10.000001 })]);
    expect(evaluatePolicy(run, parsePolicy({ rules: { maxCostPerStep: 10 } })).ok).toBe(false);
    expect(evaluatePolicy(run, parsePolicy({ rules: { maxCostPerRun: 10 } })).ok).toBe(false);
    // Exactly at the limit is allowed (documented `>` semantics).
    const atLimit = makeRun([step(0, { cost: 10 })]);
    expect(evaluatePolicy(atLimit, parsePolicy({ rules: { maxCostPerStep: 10 } })).ok).toBe(true);
  });

  it('requireSignature cannot be satisfied by an empty or absent signature', () => {
    const run = makeRun([step(0)]);
    const policy = parsePolicy({ rules: { requireSignature: true } });
    expect(evaluatePolicy(run, policy).ok).toBe(false);
    expect(evaluatePolicy({ ...run, signature: undefined }, policy).ok).toBe(false);
  });

  it('unknown rule names are rejected rather than silently ignored', () => {
    // A typo in a policy file must not fail open.
    expect(() => parsePolicy({ rules: { forbidTool: ['payments.*'] } })).toThrow();
    expect(() => parsePolicy({ rules: { maxCost: 10 } })).toThrow();
    expect(() => parsePolicy({ ruls: {} })).toThrow();
  });

  it('forbidInputText searches the whole serialized input, not just top-level strings', () => {
    const run = makeRun([step(0, { input: { args: { file: '/etc/prod-db.conf' } } })]);
    expect(
      evaluatePolicy(run, parsePolicy({ rules: { forbidInputText: ['prod-db'] } })).ok,
    ).toBe(false);
  });
});
