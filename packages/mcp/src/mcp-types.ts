/**
 * Structural types for the Model Context Protocol shapes this adapter touches.
 *
 * Deliberately NOT imported from `@modelcontextprotocol/sdk`. This package adds
 * no production dependency of its own, so:
 *   - it records whatever MCP SDK version (or hand-rolled client/server) the
 *     host application already has, instead of pinning a second copy, and
 *   - the supply chain behind an audit record stays two packages wide.
 *
 * Compatibility with the real SDK signatures is asserted at compile time in
 * `type-compat.ts` rather than assumed.
 */

/** `tools/call` request params. Extra members are preserved, never required. */
export interface CallToolParams {
  name: string;
  arguments?: Record<string, unknown> | undefined;
  _meta?: Record<string, unknown> | undefined;
}

/**
 * A `tools/call` result. Every member is optional: a tool may answer with
 * content, with `structuredContent`, with both, or with neither.
 */
export interface CallToolResultLike {
  content?: unknown;
  structuredContent?: unknown;
  isError?: boolean;
  _meta?: Record<string, unknown> | undefined;
}

/**
 * Anything that can invoke an MCP tool — an SDK `Client`, a transport shim, a
 * fake in a test. Method syntax (not a property) is deliberate: TypeScript
 * checks method parameters bivariantly, so a real client whose `callTool` takes
 * extra optional arguments (a result schema, request options) still satisfies
 * this interface.
 */
export interface McpToolCaller {
  callTool(params: CallToolParams, ...rest: never[]): Promise<unknown>;
}

/** Token/cost figures for one tool call, when the server reports any. */
export interface McpUsage {
  tokens?: number;
  cost?: number;
}
