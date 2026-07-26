import { randomBytes } from 'node:crypto';
import type { Run, Step } from '@traceglass/core';
import { startRecording, type RecordStepInput, type Recorder } from '@traceglass/sdk';
import {
  dataPayloadFromResult,
  errorOutput,
  isErrorResult,
  labelForTool,
  usageFromResult,
} from './map.js';
import type { CallToolParams, McpToolCaller, McpUsage } from './mcp-types.js';

/**
 * MCP session recorder.
 *
 * One MCP session becomes one traceglass run: every `tools/call` is a
 * `tool_call` step, hash-chained the moment it returns and journaled to disk
 * before the caller gets its result back. The chain is therefore fixed at
 * capture time — the same guarantee `@traceglass/sdk` gives, reached without
 * the host application writing any per-tool recording code.
 *
 * Steps land in COMPLETION order, which is the order the agent actually learned
 * things. Concurrent tool calls are not re-sorted by start time afterwards:
 * re-ordering a chain after the fact is exactly what a flight recorder must not
 * be able to do.
 */

/** Context handed to the `usage` hook for one completed call. */
export interface McpUsageContext {
  toolName: string;
  params: CallToolParams;
  /** The tool result, or undefined when the call threw. */
  result: unknown;
}

export interface StartMcpRecordingOptions {
  /** Run name. Defaults to `MCP session`. */
  name?: string;
  /** Explicit run id; defaults to `mcp-<date>-<hex>`. */
  id?: string;
  currency?: string;
  /** traceglass data dir; `null` for a memory-only recording. See the SDK. */
  dir?: string | null;
  /** Per-leaf commitments so payloads can be redacted later (default on). */
  redactable?: boolean;
  /** Built-in redaction patterns applied at capture time, before hashing. */
  redactPatterns?: string[];
  /**
   * Pull tokens/cost out of a result when your server reports them somewhere
   * other than the `_meta` keys `map.ts` knows about. Returning `undefined`
   * (or omitting a member) falls back to the `_meta` reading.
   */
  usage?: (ctx: McpUsageContext) => McpUsage | undefined;
}

/** One tool invocation to record. Everything except `name` is optional. */
export interface McpToolCallRecord {
  /** Tool name as sent in `tools/call`. */
  name: string;
  arguments?: Record<string, unknown> | undefined;
  /** The tool result, when the call completed. */
  result?: unknown;
  /** The thrown value, when the call failed at the transport/protocol level. */
  error?: unknown;
  /** ISO 8601 start time; defaults to now. */
  startedAt?: string;
  durationMs?: number;
  /** Overrides anything derived from the result. */
  usage?: McpUsage;
}

export interface McpRecorder {
  readonly runId: string;
  /** Record one tool invocation. Returns the chained step. */
  recordToolCall(call: McpToolCallRecord): Step;
  /**
   * Wrap an MCP client so every `tools/call` it makes is recorded. The returned
   * value is the same client type — pass it wherever the original went.
   */
  wrapClient<T extends McpToolCaller>(client: T): T;
  /**
   * Server side: wrap one tool handler so every invocation it serves is
   * recorded. `args` is the tool's argument object as MCP delivers it.
   */
  wrapToolHandler<A extends unknown[], R>(
    name: string,
    handler: (...args: A) => R | Promise<R>,
  ): (...args: A) => Promise<R>;
  /** Record a non-tool step (user input, final output, an approval, ...). */
  step(input: RecordStepInput): Step;
  /**
   * Finalize: totals, warnings, anchor, signature (if `traceglass keygen` was
   * run), store. Returns `null` for a session in which nothing was recorded —
   * an empty session is not evidence of anything, and a run with no steps
   * cannot be anchored (SPEC §6.1).
   */
  end(opts?: { status?: 'completed' | 'failed' }): Promise<Run | null>;
}

function nowMs(): number {
  return performance.now();
}

export function startMcpRecording(opts: StartMcpRecordingOptions = {}): McpRecorder {
  const runId =
    opts.id ?? `mcp-${new Date().toISOString().slice(0, 10)}-${randomBytes(3).toString('hex')}`;

  /**
   * The underlying recorder is created on the FIRST recorded step, not here.
   * An MCP session that never calls a tool would otherwise leave a stepless
   * journal on disk, which `traceglass recover` cannot finalize (a run with no
   * steps is not a record of anything). The run id is fixed up front so callers
   * can log or correlate it before anything is recorded.
   */
  let inner: Recorder | null = null;
  function recorder(): Recorder {
    inner ??= startRecording({
      name: opts.name ?? 'MCP session',
      id: runId,
      ...(opts.currency !== undefined ? { currency: opts.currency } : {}),
      ...(opts.dir !== undefined ? { dir: opts.dir } : {}),
      ...(opts.redactable !== undefined ? { redactable: opts.redactable } : {}),
      ...(opts.redactPatterns !== undefined ? { redactPatterns: opts.redactPatterns } : {}),
    });
    return inner;
  }
  let count = 0;
  let ended = false;

  function recordToolCall(call: McpToolCallRecord): Step {
    if (ended) {
      throw new Error(`MCP recording "${runId}" has already ended.`);
    }
    const failed = call.error !== undefined || isErrorResult(call.result);
    const output = call.error !== undefined ? errorOutput(call.error) : call.result;
    const dataPayload = dataPayloadFromResult(call.result);
    const fromResult = usageFromResult(call.result);
    const hook = opts.usage?.({
      toolName: call.name,
      params: { name: call.name, arguments: call.arguments },
      result: call.result,
    });
    const usage: McpUsage = { ...fromResult, ...hook, ...call.usage };

    const step = recorder().step({
      type: failed ? 'error' : 'tool_call',
      label: labelForTool(call.name),
      toolName: call.name,
      // `arguments` may legitimately be absent (a tool that takes none); an
      // empty object records "called with nothing" rather than "not recorded".
      input: call.arguments ?? {},
      ...(output !== undefined ? { output } : {}),
      ...(dataPayload !== undefined ? { dataPayload } : {}),
      ...(usage.tokens !== undefined ? { tokens: usage.tokens } : {}),
      ...(usage.cost !== undefined ? { cost: usage.cost } : {}),
      ...(call.startedAt !== undefined ? { startedAt: call.startedAt } : {}),
      ...(call.durationMs !== undefined ? { durationMs: call.durationMs } : {}),
    });
    count += 1;
    return step;
  }

  return {
    runId,

    recordToolCall,

    wrapClient<T extends McpToolCaller>(client: T): T {
      const original = client.callTool.bind(client) as (
        params: CallToolParams,
        ...rest: unknown[]
      ) => Promise<unknown>;

      const wrapped = async (params: CallToolParams, ...rest: unknown[]): Promise<unknown> => {
        const startedAt = new Date().toISOString();
        const t0 = nowMs();
        try {
          const result = await original(params, ...rest);
          recordToolCall({
            name: params.name,
            arguments: params.arguments,
            result,
            startedAt,
            durationMs: Math.round(nowMs() - t0),
          });
          return result;
        } catch (err) {
          recordToolCall({
            name: params.name,
            arguments: params.arguments,
            error: err,
            startedAt,
            durationMs: Math.round(nowMs() - t0),
          });
          throw err;
        }
      };

      // A Proxy keeps the wrapped value assignment-compatible with the original
      // client (same type, same extra methods). Every non-intercepted member is
      // read with the TARGET as receiver and bound to it, so methods that touch
      // private state still run on the real object rather than on the proxy.
      return new Proxy(client, {
        get(target, prop, _receiver) {
          if (prop === 'callTool') return wrapped;
          const value = Reflect.get(target, prop, target) as unknown;
          return typeof value === 'function'
            ? (value as (...a: unknown[]) => unknown).bind(target)
            : value;
        },
      });
    },

    wrapToolHandler<A extends unknown[], R>(
      name: string,
      handler: (...args: A) => R | Promise<R>,
    ): (...args: A) => Promise<R> {
      return async (...args: A): Promise<R> => {
        const startedAt = new Date().toISOString();
        const t0 = nowMs();
        const first = args[0];
        const argObject =
          typeof first === 'object' && first !== null && !Array.isArray(first)
            ? (first as Record<string, unknown>)
            : undefined;
        try {
          const result = await handler(...args);
          recordToolCall({
            name,
            arguments: argObject,
            result,
            startedAt,
            durationMs: Math.round(nowMs() - t0),
          });
          return result;
        } catch (err) {
          recordToolCall({
            name,
            arguments: argObject,
            error: err,
            startedAt,
            durationMs: Math.round(nowMs() - t0),
          });
          throw err;
        }
      };
    },

    step(input: RecordStepInput): Step {
      if (ended) throw new Error(`MCP recording "${runId}" has already ended.`);
      const step = recorder().step(input);
      count += 1;
      return step;
    },

    async end(endOpts: { status?: 'completed' | 'failed' } = {}): Promise<Run | null> {
      if (ended) throw new Error(`MCP recording "${runId}" has already ended.`);
      ended = true;
      if (count === 0 || inner === null) return null;
      return inner.end(endOpts);
    },
  };
}
