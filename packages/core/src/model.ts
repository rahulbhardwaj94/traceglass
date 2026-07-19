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
  'approval', // human-in-the-loop sign-off (v0.4); who/what/decision go in input/dataPayload
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

/**
 * Detached Ed25519 signature over the run's integrity anchor (§6). The signed
 * message is canonicalize({ runId, runHash, signedAt }) — signing the anchor
 * transitively covers every step via the hash chain, while runId/signedAt
 * prevent a signature being transplanted onto another run. The signature is
 * NEVER part of step hashing, so adding/removing it cannot break the chain.
 */
export const RunSignatureSchema = z.object({
  algorithm: z.literal('ed25519'),
  keyId: z.string().min(1), // first 16 hex chars of sha256(public key DER)
  publicKey: z.string().min(1), // SPKI PEM
  signature: z.string().min(1), // base64
  signedAt: z.string(), // ISO 8601
});
export type RunSignature = z.infer<typeof RunSignatureSchema>;

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
  signature: RunSignatureSchema.optional(), // absent on unsigned/legacy runs
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
