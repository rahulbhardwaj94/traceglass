import { z } from 'zod';
import { StepTypeSchema, type Run } from '../model.js';
import { assembleRun, type DraftStep } from './common.js';

/**
 * Native traceglass JSON format — a deliberately simple shape for demos and for
 * agents that don't emit OpenTelemetry. Hash/index/runId are NOT part of the
 * input; they're derived during ingestion.
 */
const NativeStepSchema = z.object({
  type: StepTypeSchema,
  label: z.string(),
  startedAt: z.string(),
  durationMs: z.number().nonnegative(),
  tokens: z.number().nonnegative().optional(),
  cost: z.number().nonnegative().optional(),
  toolName: z.string().optional(),
  input: z.unknown().optional(),
  output: z.unknown().optional(),
  dataPayload: z.unknown().optional(),
  spanId: z.string().optional(),
  parentSpanId: z.string().optional(),
});

const NativeRunSchema = z.object({
  id: z.string().min(1),
  name: z.string(),
  currency: z.string().default('USD'),
  status: z.enum(['completed', 'failed']).optional(),
  steps: z.array(NativeStepSchema),
});

export type NativeRunInput = z.input<typeof NativeRunSchema>;

/** Returns true if the value looks like native traceglass JSON. */
export function isNativeFormat(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    Array.isArray((value as { steps?: unknown }).steps) &&
    'id' in value &&
    !('resourceSpans' in value)
  );
}

/** Parse native JSON into a structural Run (hashes/warnings filled downstream). */
export function ingestNative(value: unknown): Run {
  const parsed = NativeRunSchema.parse(value);

  const drafts: DraftStep[] = parsed.steps.map((s, i) => ({
    type: s.type,
    label: s.label,
    startedAt: s.startedAt,
    durationMs: s.durationMs,
    tokens: s.tokens ?? 0,
    cost: s.cost ?? 0,
    ...(s.toolName !== undefined ? { toolName: s.toolName } : {}),
    ...(s.input !== undefined ? { input: s.input } : {}),
    ...(s.output !== undefined ? { output: s.output } : {}),
    ...(s.dataPayload !== undefined ? { dataPayload: s.dataPayload } : {}),
    spanId: s.spanId ?? `${parsed.id}-span-${i}`,
    ...(s.parentSpanId !== undefined ? { parentSpanId: s.parentSpanId } : {}),
  }));

  return assembleRun(
    {
      id: parsed.id,
      name: parsed.name,
      currency: parsed.currency,
      ...(parsed.status !== undefined ? { status: parsed.status } : {}),
    },
    drafts,
  );
}
