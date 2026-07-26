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

/**
 * One redaction event on a step: which leaf was destroyed, when, and why.
 *
 * Kept OUT of the step hash — redacting must not change the step hash (v0.6),
 * or the whole point of commitment-based erasure collapses. In `hashVersion: 2`
 * the log stops being an unverifiable free-text claim in two ways:
 *   - a committed leaf whose salt is gone MUST have a matching entry here and
 *     MUST read as the redaction marker, otherwise verification reports the
 *     leaf as ALTERED rather than as redacted (SPEC §9.4′);
 *   - the whole log can be sealed by a keyholder (`run.redactionSeal`), which
 *     is what turns "somebody says this was redacted" into "the keyholder
 *     attests to exactly these redactions".
 */
export const RedactionRecordSchema = z.object({
  path: z.string().min(1), // e.g. "input.ssn"
  at: z.string(), // ISO 8601
  reason: z.string().optional(),
  /** 'pattern' for automatic capture-time rules, 'manual' for an operator action. */
  by: z.enum(['pattern', 'manual']).optional(),
});
export type RedactionRecord = z.infer<typeof RedactionRecordSchema>;

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
  // --- v0.6 redaction (all optional; absent on pre-0.6 records) ---
  /** path -> sha256(salt + value) for each payload leaf; HASHED in place of raw values. */
  commitments: z.record(z.string()).optional(),
  /** path -> salt. A path missing here whose commitment exists has been redacted. NOT hashed. */
  salts: z.record(z.string()).optional(),
  /** Audit trail of what was removed and why. NOT hashed (it grows on redaction). */
  redactions: z.array(RedactionRecordSchema).optional(),
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

/**
 * `running` (v0.7) marks a recording still in progress — reconstructed live
 * from its journal, chain sealed only up to the latest step, runHash still
 * empty. Finalized records are only ever completed/failed.
 */
export const RunStatusSchema = z.enum(['completed', 'failed', 'running']);
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

/**
 * Ed25519 attestation over the run's redaction log (`hashVersion: 2`).
 *
 * Redaction happens AFTER signing by construction, so the run signature cannot
 * cover it — the anchor is deliberately unchanged so the original signature
 * survives. The seal is the second signature that closes the gap: it binds
 * {runId, runHash, redactionsHash, sealedAt}, so a keyholder attests to exactly
 * this set of redactions. Fabricating an entry, deleting one, or stripping the
 * seal all invalidate it, and none of them are possible without the key.
 *
 * Absent seal = the redactions are unattested: the record still declares that
 * data was destroyed (which §9.4′ enforces), but nobody has vouched for it.
 */
export const RunRedactionSealSchema = z.object({
  algorithm: z.literal('ed25519'),
  keyId: z.string().min(1),
  publicKey: z.string().min(1), // SPKI PEM
  signature: z.string().min(1), // base64
  sealedAt: z.string(), // ISO 8601; part of the sealed message
  /** sha256 over the run's redaction log; recomputed and compared on verify. */
  redactionsHash: z.string().min(1),
});
export type RunRedactionSeal = z.infer<typeof RunRedactionSealSchema>;

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
  runHash: z.string(), // the integrity anchor (§6)
  signature: RunSignatureSchema.optional(), // absent on unsigned/legacy runs
  /**
   * Which hashing rules produced this record's hashes.
   *
   * ABSENT means `tgcanon/1` — the implicit original, as published in
   * 0.3.0–0.8.0. Those records must keep verifying byte-for-byte, so the
   * absence is load-bearing and MUST NOT be filled in on an existing record.
   * New captures declare 2.
   *
   * Deliberately a plain integer rather than a literal union: a record from a
   * future version must PARSE (so it can be listed, reported on, and named in
   * an error) and then be rejected loudly by the verifier, rather than
   * exploding in the Zod layer as a malformed document.
   */
  hashVersion: z.number().int().positive().optional(),
  /** Keyholder attestation over the redaction log; `hashVersion: 2` only. */
  redactionSeal: RunRedactionSealSchema.optional(),
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
