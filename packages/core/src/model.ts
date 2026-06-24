import { z } from 'zod';

/**
 * The traceglass data model (PRD §3). This is the contract: ingestion produces
 * these shapes, analysis/integrity/store/report/web all consume them.
 *
 * Types are derived from the Zod schemas so the runtime validators and the
 * compile-time types can never drift apart.
 */

export const StepTypeSchema = z.enum([
  'user_input',
  'plan',
  'tool_call', // includes API + DB calls
  'llm_reasoning',
  'branch',
  'final_output',
  'error',
]);
export type StepType = z.infer<typeof StepTypeSchema>;

export const StepSchema = z.object({
  id: z.string().min(1), // stable unique id
  runId: z.string().min(1),
  index: z.number().int().nonnegative(), // 0-based order in the run
  type: StepTypeSchema,
  label: z.string(), // short human label, e.g. "Tool: db_query"
  startedAt: z.string(), // ISO 8601
  durationMs: z.number().nonnegative(),
  tokens: z.number().nonnegative(), // 0 if N/A
  cost: z.number().nonnegative(), // single currency unit; 0 if N/A
  toolName: z.string().optional(), // for tool_call steps
  input: z.unknown().optional(), // prompt snippet / tool args / query
  output: z.unknown().optional(), // response / tool result
  dataPayload: z.unknown().optional(), // data MUTATED or READ (compliance-critical)
  spanId: z.string(), // OTel span id (or synthesized)
  parentSpanId: z.string().optional(), // for reconstructing the tree
  hash: z.string(), // sha256 of canonicalized step content + prevHash (§6)
  prevHash: z.string(), // hash of previous step; '' for index 0
});
export type Step = z.infer<typeof StepSchema>;

export const RunTotalsSchema = z.object({
  tokens: z.number().nonnegative(),
  cost: z.number().nonnegative(),
  durationMs: z.number().nonnegative(),
  steps: z.number().int().nonnegative(),
});
export type RunTotals = z.infer<typeof RunTotalsSchema>;

export const WarningKindSchema = z.enum(['loop', 'high_cost_step', 'error']);
export type WarningKind = z.infer<typeof WarningKindSchema>;

export const WarningSchema = z.object({
  kind: WarningKindSchema,
  message: z.string(),
  stepIds: z.array(z.string()),
});
export type Warning = z.infer<typeof WarningSchema>;

export const RunStatusSchema = z.enum(['completed', 'failed']);
export type RunStatus = z.infer<typeof RunStatusSchema>;

export const RunSchema = z.object({
  id: z.string().min(1),
  name: z.string(),
  startedAt: z.string(),
  endedAt: z.string(),
  status: RunStatusSchema,
  currency: z.string(), // e.g. "INR"
  totals: RunTotalsSchema,
  warnings: z.array(WarningSchema),
  steps: z.array(StepSchema),
  runHash: z.string(), // hash of final step's hash; the integrity anchor
});
export type Run = z.infer<typeof RunSchema>;

/** Parse + validate an unknown value as a Run, throwing on failure. */
export function parseRun(value: unknown): Run {
  return RunSchema.parse(value);
}

/** Safe-parse variant returning Zod's result discriminated union. */
export function safeParseRun(value: unknown): z.SafeParseReturnType<unknown, Run> {
  return RunSchema.safeParse(value);
}
