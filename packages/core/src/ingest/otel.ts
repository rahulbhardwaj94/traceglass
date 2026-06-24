import { StepTypeSchema, type Run, type RunStatus, type StepType } from '../model.js';
import { assembleRun, type DraftRunMeta, type DraftStep } from './common.js';

/**
 * Minimal OpenTelemetry trace-export (OTLP/JSON) ingester.
 *
 * We read standard `gen_ai.*` semantic-convention attributes where available
 * (so any OTel-instrumented agent works), and traceglass-specific
 * `traceglass.*` attributes for the audit fields OTel has no convention for
 * (step type, cost, data payload). Run-level metadata lives on resource
 * attributes.
 */

interface OtelAttributeValue {
  stringValue?: string;
  intValue?: string | number;
  doubleValue?: number;
  boolValue?: boolean;
}
interface OtelAttribute {
  key: string;
  value: OtelAttributeValue;
}
interface OtelSpan {
  spanId?: string;
  parentSpanId?: string;
  name?: string;
  startTimeUnixNano?: string | number;
  endTimeUnixNano?: string | number;
  attributes?: OtelAttribute[];
  status?: { code?: number };
}
interface OtelScopeSpans {
  spans?: OtelSpan[];
}
interface OtelResourceSpans {
  resource?: { attributes?: OtelAttribute[] };
  scopeSpans?: OtelScopeSpans[];
}
interface OtelExport {
  resourceSpans?: OtelResourceSpans[];
}

type AttrMap = Record<string, string | number | boolean>;

function attrsToMap(attrs: OtelAttribute[] | undefined): AttrMap {
  const map: AttrMap = {};
  for (const a of attrs ?? []) {
    const v = a.value ?? {};
    if (v.stringValue !== undefined) map[a.key] = v.stringValue;
    else if (v.intValue !== undefined) map[a.key] = Number(v.intValue);
    else if (v.doubleValue !== undefined) map[a.key] = v.doubleValue;
    else if (v.boolValue !== undefined) map[a.key] = v.boolValue;
  }
  return map;
}

function num(v: string | number | boolean | undefined): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN;
  return Number.isFinite(n) ? n : 0;
}

/** Parse a value that may be a JSON string into structured data, else return as-is. */
function maybeJson(v: string | number | boolean | undefined): unknown {
  if (typeof v !== 'string') return v;
  const trimmed = v.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return v;
    }
  }
  return v;
}

function deriveType(attrs: AttrMap, name: string): StepType {
  const explicit = attrs['traceglass.step.type'];
  if (typeof explicit === 'string') {
    const r = StepTypeSchema.safeParse(explicit);
    if (r.success) return r.data;
  }
  // Heuristic fallback from gen_ai conventions / span name.
  if (attrs['gen_ai.tool.name'] !== undefined || /tool|db|query|api/i.test(name)) {
    return 'tool_call';
  }
  if (/reason|think|llm|completion/i.test(name)) return 'llm_reasoning';
  if (/plan/i.test(name)) return 'plan';
  if (/input|prompt|user/i.test(name)) return 'user_input';
  if (/output|final|answer|decision/i.test(name)) return 'final_output';
  return 'llm_reasoning';
}

function nanoToIso(nano: string | number | undefined): string {
  const n = typeof nano === 'number' ? nano : typeof nano === 'string' ? Number(nano) : 0;
  return new Date(Math.round(n / 1e6)).toISOString();
}

/** Returns true if the value looks like an OTLP/JSON trace export. */
export function isOtelFormat(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    Array.isArray((value as { resourceSpans?: unknown }).resourceSpans)
  );
}

export function ingestOtel(value: unknown): Run {
  const root = value as OtelExport;
  const resourceSpans = root.resourceSpans ?? [];

  // Run metadata from the first resource's attributes.
  const resourceAttrs = attrsToMap(resourceSpans[0]?.resource?.attributes);
  const meta: DraftRunMeta = {
    id: String(resourceAttrs['traceglass.run.id'] ?? 'otel-run'),
    name: String(resourceAttrs['traceglass.run.name'] ?? 'OpenTelemetry run'),
    currency: String(resourceAttrs['traceglass.run.currency'] ?? 'USD'),
  };
  const explicitStatus = resourceAttrs['traceglass.run.status'];
  if (explicitStatus === 'completed' || explicitStatus === 'failed') {
    meta.status = explicitStatus as RunStatus;
  }

  const drafts: DraftStep[] = [];
  for (const rs of resourceSpans) {
    for (const ss of rs.scopeSpans ?? []) {
      for (const span of ss.spans ?? []) {
        const attrs = attrsToMap(span.attributes);
        const name = span.name ?? 'span';
        const startMs = num(span.startTimeUnixNano) / 1e6;
        const endMs = num(span.endTimeUnixNano) / 1e6;
        const durationMs = Math.max(0, Math.round(endMs - startMs));

        const inputTokens = num(attrs['gen_ai.usage.input_tokens']);
        const outputTokens = num(attrs['gen_ai.usage.output_tokens']);
        const totalTokens = num(attrs['gen_ai.usage.total_tokens']);
        const tokens = totalTokens > 0 ? totalTokens : inputTokens + outputTokens;

        const toolName =
          (attrs['gen_ai.tool.name'] as string | undefined) ??
          (attrs['traceglass.tool.name'] as string | undefined);

        const draft: DraftStep = {
          type: deriveType(attrs, name),
          label: String(attrs['traceglass.step.label'] ?? name),
          startedAt: nanoToIso(span.startTimeUnixNano),
          durationMs,
          tokens,
          cost: num(attrs['traceglass.cost']),
          spanId: span.spanId ?? `${meta.id}-span-${drafts.length}`,
        };
        if (toolName !== undefined) draft.toolName = toolName;
        if (span.parentSpanId) draft.parentSpanId = span.parentSpanId;

        const input = maybeJson(attrs['gen_ai.prompt'] ?? attrs['traceglass.input']);
        if (input !== undefined) draft.input = input;
        const output = maybeJson(attrs['gen_ai.completion'] ?? attrs['traceglass.output']);
        if (output !== undefined) draft.output = output;
        const payload = maybeJson(attrs['traceglass.data_payload']);
        if (payload !== undefined) draft.dataPayload = payload;

        drafts.push(draft);
      }
    }
  }

  return assembleRun(meta, drafts);
}
