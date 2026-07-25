import { z } from 'zod';
import type { Run, Step, WarningKind } from '../model.js';
import { WarningKindSchema } from '../model.js';

/**
 * Declarative guardrail policy (v0.4). A policy is a plain JSON file asserting
 * what a recorded run was ALLOWED to do; `evaluatePolicy` replays those
 * assertions against the evidence. This is read-side governance: it never
 * mutates the run, so a policy check on a .tgev export is as authoritative as
 * one against the store.
 *
 * Tool-name patterns support a single trailing or leading `*` wildcard
 * ("payments.*", "*_delete") — enough for namespacing without a glob dep.
 */

export const PolicyRulesSchema = z
  .object({
    /** Fail if totals.cost exceeds this (in the run's own currency). */
    maxCostPerRun: z.number().positive().optional(),
    /** Fail if totals.tokens exceeds this. */
    maxTokensPerRun: z.number().positive().optional(),
    /** Fail if the run has more steps than this. */
    maxSteps: z.number().int().positive().optional(),
    /** Fail any single step costing more than this. */
    maxCostPerStep: z.number().positive().optional(),
    /** Tool-name patterns the agent must never call. */
    forbidTools: z.array(z.string().min(1)).optional(),
    /** Tool-name patterns that require a PRECEDING `approval` step. */
    requireApprovalFor: z.array(z.string().min(1)).optional(),
    /**
     * Fail any step whose input contains one of these text fragments
     * (case-insensitive). Built for coding agents: ".env", "prod-db",
     * "rm -rf" — "the agent must never touch X" as a one-liner.
     */
    forbidInputText: z.array(z.string().min(1)).optional(),
    /** Fail if the run is not cryptographically signed. */
    requireSignature: z.boolean().optional(),
    /** Warning kinds that fail the check (e.g. ["loop"]). */
    forbidWarnings: z.array(WarningKindSchema).optional(),
  })
  .strict();

export const PolicySchema = z
  .object({
    name: z.string().optional(),
    rules: PolicyRulesSchema,
  })
  .strict();

export type PolicyRules = z.infer<typeof PolicyRulesSchema>;
export type Policy = z.infer<typeof PolicySchema>;

export interface PolicyViolation {
  rule: string;
  message: string;
  stepIds: string[];
}

export interface PolicyResult {
  ok: boolean;
  policyName: string | null;
  violations: PolicyViolation[];
}

/** Parse + validate an unknown value as a Policy, throwing on failure. */
export function parsePolicy(value: unknown): Policy {
  return PolicySchema.parse(value);
}

/**
 * Fold a tool name to its matching form.
 *
 * A guardrail is only as good as the spelling it insists on. Raw UTF-16
 * comparison let "Payments.Refund", " payments.refund", and a name carrying a
 * zero-width space all walk past a `forbidTools: ['payments.refund']` rule —
 * the rule read as enforced and stopped nothing. Normalising both sides closes
 * the trivial evasions: NFKC folds compatibility forms, the strip removes
 * zero-width and bidi controls that render identically to nothing, and the
 * case/whitespace fold covers the rest.
 *
 * This deliberately errs toward matching MORE: a false positive on a guardrail
 * is a blocked run somebody investigates, while a false negative is the
 * forbidden tool running unnoticed.
 */
function foldToolName(name: string): string {
  return name
    .normalize('NFKC')
    .replace(/[\u200B-\u200F\u2060\uFEFF]/g, '')
    .trim()
    .toLowerCase();
}

/** Match a tool name against a pattern with one optional leading/trailing `*`. */
export function toolMatches(toolName: string, pattern: string): boolean {
  const name = foldToolName(toolName);
  const pat = foldToolName(pattern);
  if (pat === '*') return true;
  if (pat.startsWith('*')) return name.endsWith(pat.slice(1));
  if (pat.endsWith('*')) return name.startsWith(pat.slice(0, -1));
  return name === pat;
}

function toolSteps(run: Run): Step[] {
  return run.steps.filter((s) => s.type === 'tool_call' && s.toolName !== undefined);
}

/** Evaluate every rule in the policy against a run. Pure. */
export function evaluatePolicy(run: Run, policy: Policy): PolicyResult {
  const r = policy.rules;
  const violations: PolicyViolation[] = [];

  if (r.maxCostPerRun !== undefined && run.totals.cost > r.maxCostPerRun) {
    violations.push({
      rule: 'maxCostPerRun',
      message: `Run cost ${run.currency} ${run.totals.cost.toFixed(2)} exceeds the limit of ${r.maxCostPerRun}.`,
      stepIds: [],
    });
  }

  if (r.maxTokensPerRun !== undefined && run.totals.tokens > r.maxTokensPerRun) {
    violations.push({
      rule: 'maxTokensPerRun',
      message: `Run used ${run.totals.tokens} tokens, exceeding the limit of ${r.maxTokensPerRun}.`,
      stepIds: [],
    });
  }

  if (r.maxSteps !== undefined && run.totals.steps > r.maxSteps) {
    violations.push({
      rule: 'maxSteps',
      message: `Run has ${run.totals.steps} steps, exceeding the limit of ${r.maxSteps}.`,
      stepIds: [],
    });
  }

  if (r.maxCostPerStep !== undefined) {
    const over = run.steps.filter((s) => s.cost > r.maxCostPerStep!);
    if (over.length > 0) {
      violations.push({
        rule: 'maxCostPerStep',
        message: `${over.length} step(s) cost more than ${r.maxCostPerStep} each (first: #${over[0]!.index} "${over[0]!.label}").`,
        stepIds: over.map((s) => s.id),
      });
    }
  }

  for (const pattern of r.forbidTools ?? []) {
    const hits = toolSteps(run).filter((s) => toolMatches(s.toolName!, pattern));
    if (hits.length > 0) {
      violations.push({
        rule: 'forbidTools',
        message: `Forbidden tool "${pattern}" was called ${hits.length} time(s) (first at step #${hits[0]!.index}).`,
        stepIds: hits.map((s) => s.id),
      });
    }
  }

  for (const pattern of r.requireApprovalFor ?? []) {
    // Each matching tool_call must have an `approval` step EARLIER in the run.
    const unapproved = toolSteps(run).filter(
      (s) =>
        toolMatches(s.toolName!, pattern) &&
        !run.steps.some((a) => a.type === 'approval' && a.index < s.index),
    );
    if (unapproved.length > 0) {
      violations.push({
        rule: 'requireApprovalFor',
        message: `Tool "${pattern}" was called without a preceding approval step (${unapproved.length} time(s), first at step #${unapproved[0]!.index}).`,
        stepIds: unapproved.map((s) => s.id),
      });
    }
  }

  for (const needle of r.forbidInputText ?? []) {
    const lower = needle.toLowerCase();
    const hits = run.steps.filter(
      (s) => s.input !== undefined && JSON.stringify(s.input).toLowerCase().includes(lower),
    );
    if (hits.length > 0) {
      violations.push({
        rule: 'forbidInputText',
        message: `Forbidden input text "${needle}" appeared in ${hits.length} step(s) (first at step #${hits[0]!.index} "${hits[0]!.label}").`,
        stepIds: hits.map((s) => s.id),
      });
    }
  }

  if (r.requireSignature === true && !run.signature) {
    violations.push({
      rule: 'requireSignature',
      message: 'Run is not cryptographically signed (run `traceglass keygen` before ingest).',
      stepIds: [],
    });
  }

  for (const kind of (r.forbidWarnings ?? []) as WarningKind[]) {
    const hits = run.warnings.filter((w) => w.kind === kind);
    for (const w of hits) {
      violations.push({
        rule: 'forbidWarnings',
        message: `Forbidden warning "${kind}": ${w.message}`,
        stepIds: w.stepIds,
      });
    }
  }

  return { ok: violations.length === 0, policyName: policy.name ?? null, violations };
}
