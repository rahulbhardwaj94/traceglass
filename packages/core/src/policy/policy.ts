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

/** Match a tool name against a pattern with one optional leading/trailing `*`. */
export function toolMatches(toolName: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern.startsWith('*')) return toolName.endsWith(pattern.slice(1));
  if (pattern.endsWith('*')) return toolName.startsWith(pattern.slice(0, -1));
  return toolName === pattern;
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
