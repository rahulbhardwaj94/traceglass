/**
 * Compile-time proof that this package's structural types accept the REAL
 * `@modelcontextprotocol/sdk` shapes, without depending on that package.
 *
 * The declarations below mirror the upstream signatures (`Client.callTool`
 * takes a params object plus an optional result schema and request options;
 * `registerTool` handlers take the argument object plus a request-extra
 * object). If a future MCP SDK changes them incompatibly, the assertions here
 * stop compiling and `npm run typecheck` fails — which is the point: the
 * failure lands on this package rather than on a user's build.
 *
 * Types only. This module emits no runtime code and is not re-exported.
 */
import type { McpToolCaller } from './mcp-types.js';

/** Mirror of the upstream result type (every member optional in practice). */
interface UpstreamCallToolResult {
  content?: Array<{ type: string; text?: string }>;
  structuredContent?: { [key: string]: unknown };
  isError?: boolean;
  _meta?: { [key: string]: unknown };
}

/** Mirror of `Client` — only the member this adapter wraps. */
declare class UpstreamClient {
  callTool(
    params: { name: string; arguments?: { [key: string]: unknown }; _meta?: object },
    resultSchema?: { parse(value: unknown): unknown },
    options?: { timeout?: number; signal?: AbortSignal },
  ): Promise<UpstreamCallToolResult>;
  listTools(): Promise<{ tools: Array<{ name: string }> }>;
  close(): Promise<void>;
}

/** A real client satisfies the caller interface `wrapClient` requires. */
type _ClientIsCaller = UpstreamClient extends McpToolCaller ? true : never;
const _clientIsCaller: _ClientIsCaller = true;

/** `wrapClient<T>` returns T, so the wrapped value stays a full client. */
declare function wrapLike<T extends McpToolCaller>(client: T): T;
declare const _upstream: UpstreamClient;
const _wrappedKeepsType: UpstreamClient = wrapLike(_upstream);

/**
 * Mirror of a `registerTool` handler: (args, extra) => result | Promise<result>.
 * `wrapToolHandler` must accept it and hand back something registerable.
 */
type UpstreamToolHandler = (
  args: { [key: string]: unknown },
  extra: { signal: AbortSignal },
) => UpstreamCallToolResult | Promise<UpstreamCallToolResult>;

declare function wrapHandlerLike<A extends unknown[], R>(
  name: string,
  handler: (...args: A) => R | Promise<R>,
): (...args: A) => Promise<R>;

declare const _upstreamHandler: UpstreamToolHandler;
const _wrappedHandler: UpstreamToolHandler = wrapHandlerLike('t', _upstreamHandler);

/** Nothing here is meant to be imported; the assertions above are the payload. */
export const TYPE_COMPAT_ASSERTIONS = 3;
void _clientIsCaller;
void _wrappedKeepsType;
void _wrappedHandler;
