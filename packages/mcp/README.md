# @traceglass/mcp

Record **Model Context Protocol** tool calls as [traceglass](https://www.npmjs.com/package/traceglass)
runs. One MCP session becomes one hash-chained, signed record: every `tools/call` is
chained and journaled the moment it returns, so the tamper window closes at capture
time — not at ingest.

```bash
npm install @traceglass/mcp
```

## Wrap the client — every tool it calls is recorded

```ts
import { startMcpRecording } from '@traceglass/mcp';

const rec = startMcpRecording({ name: 'support agent — ticket 8812', currency: 'INR' });
const mcp = rec.wrapClient(client); // your @modelcontextprotocol/sdk Client

rec.step({ type: 'user_input', label: 'Refund request', input: { ticket: '8812' } });
await mcp.callTool({ name: 'lookup_order', arguments: { id: '4471' } });
await mcp.callTool({ name: 'issue_refund', arguments: { id: '4471', amount: 1200 } });
rec.step({ type: 'final_output', label: 'Refund issued' });

const run = await rec.end(); // verified, signed (if `traceglass keygen` was run), stored
console.log(run?.id, run?.runHash);
```

`wrapClient` returns the same client type — pass it wherever the original went. Replay
with `npx traceglass open --id <runId>`, verify with `npx traceglass verify <runId>`.

## What lands in each step

| Step field    | From                                                                           |
| ------------- | ------------------------------------------------------------------------------ |
| `type`        | `tool_call`, or `error` when the result has `isError: true` or the call throws |
| `toolName`    | the `tools/call` tool name                                                     |
| `input`       | the call's `arguments` (`{}` when a tool takes none)                           |
| `output`      | the whole result, verbatim                                                     |
| `dataPayload` | `structuredContent` — the data the agent actually read                         |
| `tokens`      | `_meta["traceglass/tokens"]` (or the `usage` hook)                             |
| `cost`        | `_meta["traceglass/cost"]` (or the `usage` hook)                               |

MCP has no convention for tokens or cost. If your server reports them somewhere else,
pass `usage: ({ result }) => ({ tokens, cost })` and it wins over the `_meta` reading.

## Server side

```ts
server.registerTool('summarize', schema, rec.wrapToolHandler('summarize', handler));
```

- **Order is capture order.** Concurrent tool calls are chained as they complete and are
  never re-sorted afterwards — re-ordering a sealed chain is the one thing a flight
  recorder must not be able to do.
- **Crash-safe:** if the process dies mid-session, `npx traceglass recover` finalizes the
  journal into a `failed` run whose chain still verifies up to the crash point.
- **Local-first:** everything is written under `~/.traceglass` (or `TRACEGLASS_HOME`).
  Zero network egress, and no production dependency outside traceglass itself — this
  package speaks MCP structurally, so it works with whatever MCP SDK you already have.
- `end()` returns `null` for a session in which nothing was recorded: an empty session is
  not evidence of anything, and no journal is left behind for `recover` to trip over.
