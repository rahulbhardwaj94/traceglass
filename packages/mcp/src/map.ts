import type { CallToolResultLike, McpUsage } from './mcp-types.js';

/**
 * MCP → traceglass step mapping.
 *
 * MCP has no convention for cost or tokens, so this reads two OPTIONAL `_meta`
 * keys on the tool result. `_meta` keys are namespaced by the spec, hence the
 * `traceglass/` prefix; the dotted spelling is accepted too because plenty of
 * emitters reach for it out of habit.
 *
 * Anything a server reports elsewhere is reachable through the `usage` hook on
 * `startMcpRecording` — this module stays free of per-server guesswork.
 */
export const TOKENS_META_KEYS = ['traceglass/tokens', 'traceglass.tokens'] as const;
export const COST_META_KEYS = ['traceglass/cost', 'traceglass.cost'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A finite, non-negative number, or undefined. Step fields reject the rest. */
function nonNegative(value: unknown): number | undefined {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? Number(value) : NaN;
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

function firstOf(meta: Record<string, unknown>, keys: readonly string[]): number | undefined {
  for (const key of keys) {
    const n = nonNegative(meta[key]);
    if (n !== undefined) return n;
  }
  return undefined;
}

/** Read `_meta`-reported tokens/cost off a tool result. Absent members stay absent. */
export function usageFromResult(result: unknown): McpUsage {
  if (!isRecord(result)) return {};
  const meta = (result as CallToolResultLike)._meta;
  if (!isRecord(meta)) return {};
  const tokens = firstOf(meta, TOKENS_META_KEYS);
  const cost = firstOf(meta, COST_META_KEYS);
  return {
    ...(tokens !== undefined ? { tokens } : {}),
    ...(cost !== undefined ? { cost } : {}),
  };
}

/**
 * Did the tool answer with a protocol-level error? MCP reports tool failures
 * in-band (`isError: true` on a successful JSON-RPC response), so a failed tool
 * call is invisible unless this flag is read.
 */
export function isErrorResult(result: unknown): boolean {
  return isRecord(result) && (result as CallToolResultLike).isError === true;
}

/**
 * The data the agent actually received, for the compliance-critical
 * `dataPayload` field: `structuredContent` when the tool returns it, otherwise
 * undefined (the full result is already recorded verbatim as `output`).
 */
export function dataPayloadFromResult(result: unknown): unknown {
  if (!isRecord(result)) return undefined;
  return (result as CallToolResultLike).structuredContent;
}

/** Human-readable step label, matching the SDK's `Tool: <name>` convention. */
export function labelForTool(toolName: string): string {
  return `Tool: ${toolName}`;
}

/**
 * Normalize a thrown value into something JSON-serializable for the record.
 * A transport rejection must still produce a step, so this never throws:
 * a circular or unserializable value degrades to a placeholder.
 */
export function errorOutput(err: unknown): { error: string; name?: string } {
  if (err instanceof Error) {
    return { error: err.message, name: err.name };
  }
  if (typeof err === 'string') return { error: err };
  try {
    const json = JSON.stringify(err);
    return { error: json ?? `[${typeof err}]` };
  } catch {
    return { error: '[unserializable error]' };
  }
}
