import { StepTypeSchema, type StepType } from '@traceglass/core';
import { hrToMs, parentSpanIdOf, type AttributesLike, type RecordableSpan } from './span-types.js';
import type { WriterStepInput } from './writer.js';

/**
 * Span → step mapping.
 *
 * The attribute names are deliberately the SAME set the offline OTLP ingester
 * consumes (`packages/core/src/ingest/otel.ts`): `gen_ai.*` where a semantic
 * convention exists, `traceglass.*` for the audit fields OTel has no convention
 * for. A span that produces a given step through `traceglass ingest` produces
 * the same step through this processor.
 *
 * Two deliberate additions over the ingester, both documented in the README:
 *   1. a span whose status code is ERROR (2) becomes an `error` step, so a
 *      failed run is recorded as failed. The ingester ignores span status.
 *   2. attributes not copied verbatim into a step field are recorded as
 *      `dataPayload.attributes` (unless `traceglass.data_payload` is set), so
 *      `gen_ai.request.model` and friends survive into the record instead of
 *      being dropped. Those keys are DOTTED, which is precisely the payload
 *      shape `tgcanon/2` had to fix — see the tests.
 */

/** OTel `SpanStatusCode.ERROR`. */
export const SPAN_STATUS_ERROR = 2;

/** Attributes copied verbatim into a step field, hence excluded from the snapshot. */
export const MAPPED_ATTRIBUTES = [
  'traceglass.step.type',
  'traceglass.step.label',
  'traceglass.tool.name',
  'traceglass.cost',
  'traceglass.input',
  'traceglass.output',
  'traceglass.data_payload',
  'gen_ai.tool.name',
  'gen_ai.prompt',
  'gen_ai.completion',
] as const;

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** Finite non-negative number, else 0 — step fields reject anything else. */
function num(value: unknown): number {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

/**
 * Parse a value that may be a JSON string into structured data, else return it
 * as-is. Same rule as the ingester: attributes are flat scalars on the wire, so
 * a JSON-encoded prompt or payload has to be re-inflated to be readable (and
 * redactable leaf by leaf) in the record.
 */
export function maybeJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(trimmed) as unknown;
    } catch {
      return value;
    }
  }
  return value;
}

/** Token count: the reported total, else input+output, else the legacy names. */
export function tokensFrom(attrs: AttributesLike): number {
  const total = num(attrs['gen_ai.usage.total_tokens']);
  if (total > 0) return total;
  const input = num(attrs['gen_ai.usage.input_tokens']) || num(attrs['gen_ai.usage.prompt_tokens']);
  const output =
    num(attrs['gen_ai.usage.output_tokens']) || num(attrs['gen_ai.usage.completion_tokens']);
  return input + output;
}

/**
 * Step type: an explicit `traceglass.step.type` wins, then an ERROR span
 * status, then the ingester's heuristics over the gen_ai attributes and the
 * span name.
 */
export function deriveStepType(attrs: AttributesLike, name: string, statusCode?: number): StepType {
  const explicit = str(attrs['traceglass.step.type']);
  if (explicit !== undefined) {
    const parsed = StepTypeSchema.safeParse(explicit);
    if (parsed.success) return parsed.data;
  }
  if (statusCode === SPAN_STATUS_ERROR) return 'error';
  if (attrs['gen_ai.tool.name'] !== undefined || /tool|db|query|api/i.test(name))
    return 'tool_call';
  if (/reason|think|llm|completion/i.test(name)) return 'llm_reasoning';
  if (/plan/i.test(name)) return 'plan';
  if (/input|prompt|user/i.test(name)) return 'user_input';
  if (/output|final|answer|decision/i.test(name)) return 'final_output';
  return 'llm_reasoning';
}

/**
 * Attributes not already copied into a step field, dotted keys intact.
 * Undefined values are dropped (OTel allows them; JSON does not carry them).
 */
export function attributeSnapshot(attrs: AttributesLike): Record<string, unknown> {
  const skip = new Set<string>(MAPPED_ATTRIBUTES);
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(attrs)) {
    if (skip.has(key)) continue;
    const value = attrs[key];
    if (value === undefined) continue;
    out[key] = value;
  }
  return out;
}

export interface SpanMapOptions {
  /** Record unmapped span attributes as `dataPayload.attributes` (default true). */
  recordAttributes?: boolean;
}

/** Map one ended span onto the step the writer will chain. */
export function spanToStep(span: RecordableSpan, opts: SpanMapOptions = {}): WriterStepInput {
  const attrs = span.attributes;
  const name = span.name;
  const startMs = hrToMs(span.startTime);
  const endMs = hrToMs(span.endTime);
  const durationMs = span.duration
    ? Math.max(0, Math.round(hrToMs(span.duration)))
    : Math.max(0, Math.round(endMs - startMs));

  const toolName = str(attrs['gen_ai.tool.name']) ?? str(attrs['traceglass.tool.name']);
  const input = maybeJson(attrs['gen_ai.prompt'] ?? attrs['traceglass.input']);
  const output = maybeJson(attrs['gen_ai.completion'] ?? attrs['traceglass.output']);
  const explicitPayload = maybeJson(attrs['traceglass.data_payload']);

  let dataPayload: unknown = explicitPayload;
  if (dataPayload === undefined && opts.recordAttributes !== false) {
    const snapshot = attributeSnapshot(attrs);
    if (Object.keys(snapshot).length > 0) dataPayload = { attributes: snapshot };
  }

  const parentSpanId = parentSpanIdOf(span);
  const step: WriterStepInput = {
    type: deriveStepType(attrs, name, span.status?.code),
    label: str(attrs['traceglass.step.label']) ?? name,
    startedAt: new Date(Math.round(startMs)).toISOString(),
    durationMs,
    tokens: tokensFrom(attrs),
    cost: num(attrs['traceglass.cost']),
    spanId: span.spanContext().spanId,
  };
  if (toolName !== undefined) step.toolName = toolName;
  if (parentSpanId !== '') step.parentSpanId = parentSpanId;
  if (input !== undefined) step.input = input;
  if (output !== undefined) step.output = output;
  if (dataPayload !== undefined) step.dataPayload = dataPayload;
  return step;
}
