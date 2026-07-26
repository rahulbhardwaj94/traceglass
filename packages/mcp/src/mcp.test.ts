import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RunStore, verifyRun, verifyRunFull } from '@traceglass/core';
import { startMcpRecording } from './recorder.js';
import type { CallToolParams } from './mcp-types.js';

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-mcp-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

/**
 * Stands in for `@modelcontextprotocol/sdk`'s Client: the same three-argument
 * `callTool` signature, plus private state and a second method, so the wrapper
 * is exercised against something a Proxy can actually get wrong.
 */
class FakeClient {
  private calls = 0;
  constructor(private readonly reply: (params: CallToolParams) => unknown) {}

  async callTool(
    params: CallToolParams,
    _resultSchema?: unknown,
    _options?: unknown,
  ): Promise<unknown> {
    this.calls += 1;
    await Promise.resolve();
    const result = this.reply(params);
    if (result instanceof Error) throw result;
    return result;
  }

  callCount(): number {
    return this.calls;
  }
}

describe('startMcpRecording — client wrapping', () => {
  it('records a tool call as a verifying, stored run', async () => {
    const client = new FakeClient(() => ({
      content: [{ type: 'text', text: 'ok' }],
      structuredContent: { rows: 2 },
      _meta: { 'traceglass/tokens': 812, 'traceglass/cost': 0.4 },
    }));
    const rec = startMcpRecording({ name: 'support session', dir: home, id: 'mcp-t1' });
    const wrapped = rec.wrapClient(client);

    await wrapped.callTool({ name: 'search_docs', arguments: { q: 'refunds' } });
    const run = await rec.end();

    expect(run).not.toBeNull();
    expect(run!.steps).toHaveLength(1);
    const step = run!.steps[0]!;
    expect(step.type).toBe('tool_call');
    expect(step.toolName).toBe('search_docs');
    expect(step.label).toBe('Tool: search_docs');
    expect(step.input).toEqual({ q: 'refunds' });
    expect(step.dataPayload).toEqual({ rows: 2 });
    expect(step.tokens).toBe(812);
    expect(step.cost).toBe(0.4);
    expect(verifyRun(run!).ok).toBe(true);

    const store = new RunStore(join(home, 'traceglass.sqlite'));
    const stored = store.getRun('mcp-t1');
    store.close();
    expect(stored).not.toBeNull();
    expect(verifyRunFull(stored!).ok).toBe(true);
  });

  it('passes the result through and keeps the client usable', async () => {
    const client = new FakeClient(() => ({ content: [{ type: 'text', text: 'hi' }] }));
    const rec = startMcpRecording({ dir: null });
    const wrapped = rec.wrapClient(client);

    const result = await wrapped.callTool({ name: 'ping' });
    expect(result).toEqual({ content: [{ type: 'text', text: 'hi' }] });
    // Non-intercepted methods still run against the real client, not the proxy.
    expect(wrapped.callCount()).toBe(1);
    await rec.end();
  });

  it('records an in-band MCP tool error as an error step and fails the run', async () => {
    const client = new FakeClient(() => ({
      isError: true,
      content: [{ type: 'text', text: 'permission denied' }],
    }));
    const rec = startMcpRecording({ dir: null });
    await rec.wrapClient(client).callTool({ name: 'delete_account', arguments: { id: 7 } });
    const run = await rec.end();

    expect(run!.steps[0]!.type).toBe('error');
    expect(run!.status).toBe('failed');
    expect(verifyRun(run!).ok).toBe(true);
  });

  it('records a thrown transport error and rethrows it unchanged', async () => {
    const boom = new Error('connection closed');
    const client = new FakeClient(() => boom);
    const rec = startMcpRecording({ dir: null });
    const wrapped = rec.wrapClient(client);

    await expect(wrapped.callTool({ name: 'flaky' })).rejects.toThrow('connection closed');
    const run = await rec.end();
    expect(run!.steps[0]!.type).toBe('error');
    expect(run!.steps[0]!.output).toEqual({ error: 'connection closed', name: 'Error' });
  });

  it('keeps completion order for concurrent calls and never re-chains', async () => {
    const client = new FakeClient((p) => ({ content: [{ type: 'text', text: p.name }] }));
    const rec = startMcpRecording({ dir: null });
    const wrapped = rec.wrapClient(client);

    await Promise.all([
      wrapped.callTool({ name: 'a' }),
      wrapped.callTool({ name: 'b' }),
      wrapped.callTool({ name: 'c' }),
    ]);
    const run = await rec.end();

    expect(run!.steps.map((s) => s.toolName)).toEqual(['a', 'b', 'c']);
    expect(run!.steps.map((s) => s.index)).toEqual([0, 1, 2]);
    expect(run!.steps[0]!.prevHash).toBe('');
    expect(run!.steps[1]!.prevHash).toBe(run!.steps[0]!.hash);
    expect(verifyRun(run!).ok).toBe(true);
  });
});

describe('startMcpRecording — payload handling', () => {
  it('records dotted keys in tool arguments without breaking the chain', async () => {
    // Dotted keys in a payload are the exact shape that crashed the recorder
    // before tgcanon/2 — and MCP arguments are arbitrary caller JSON.
    const args = {
      'filter.field': 'status',
      'filter.value': 'open',
      nested: { 'a.b': { 'c.d': 1 } },
    };
    const client = new FakeClient(() => ({
      structuredContent: { 'gen_ai.request.model': 'claude-x', 'result.count': 3 },
    }));
    const rec = startMcpRecording({ dir: null });
    await rec.wrapClient(client).callTool({ name: 'query', arguments: args });
    const run = await rec.end();

    const step = run!.steps[0]!;
    expect(step.input).toEqual(args);
    expect(run!.hashVersion).toBe(2);
    expect(verifyRun(run!).ok).toBe(true);
    // Path segments are escaped, so a literal dot cannot collide with nesting.
    expect(Object.keys(step.commitments ?? {})).toContain('input.filter\\.field');
    expect(Object.keys(step.commitments ?? {})).toContain('input.nested.a\\.b.c\\.d');
    expect(Object.keys(step.commitments ?? {})).toContain('dataPayload.gen_ai\\.request\\.model');
  });

  it('reads dotted _meta usage keys as well as the namespaced ones', async () => {
    const client = new FakeClient(() => ({
      _meta: { 'traceglass.tokens': 5, 'traceglass.cost': 1 },
    }));
    const rec = startMcpRecording({ dir: null });
    await rec.wrapClient(client).callTool({ name: 'x' });
    const run = await rec.end();
    expect(run!.steps[0]!.tokens).toBe(5);
    expect(run!.steps[0]!.cost).toBe(1);
  });

  it('lets the usage hook supply figures the server reports elsewhere', async () => {
    const client = new FakeClient(() => ({ structuredContent: { usage: { total: 40 } } }));
    const rec = startMcpRecording({
      dir: null,
      usage: ({ result }) => {
        const structured = (result as { structuredContent?: { usage?: { total?: number } } })
          .structuredContent;
        const total = structured?.usage?.total;
        return total === undefined ? undefined : { tokens: total };
      },
    });
    await rec.wrapClient(client).callTool({ name: 'x' });
    const run = await rec.end();
    expect(run!.steps[0]!.tokens).toBe(40);
  });

  it('scrubs capture-time patterns before anything is hashed', async () => {
    const client = new FakeClient(() => ({ structuredContent: { email: 'lead@example.com' } }));
    const rec = startMcpRecording({ dir: null, redactPatterns: ['email'] });
    await rec.wrapClient(client).callTool({ name: 'lookup', arguments: { to: 'a@b.io' } });
    const run = await rec.end();

    const step = run!.steps[0]!;
    expect(JSON.stringify(step.input)).not.toContain('a@b.io');
    expect(JSON.stringify(step.dataPayload)).not.toContain('lead@example.com');
    expect(step.redactions?.length).toBeGreaterThan(0);
    expect(verifyRun(run!).ok).toBe(true);
  });
});

describe('startMcpRecording — server side and lifecycle', () => {
  it('wraps a tool handler and records what it served', async () => {
    const rec = startMcpRecording({ dir: null });
    const handler = rec.wrapToolHandler(
      'summarize',
      async (args: { text: string }, _extra: unknown) => {
        await Promise.resolve();
        return { content: [{ type: 'text', text: args.text.slice(0, 3) }] };
      },
    );

    const result = await handler({ text: 'hello world' }, { signal: undefined });
    expect(result).toEqual({ content: [{ type: 'text', text: 'hel' }] });

    const run = await rec.end();
    expect(run!.steps[0]!.toolName).toBe('summarize');
    expect(run!.steps[0]!.input).toEqual({ text: 'hello world' });
  });

  it('records non-tool steps alongside tool calls', async () => {
    const rec = startMcpRecording({ dir: null });
    rec.step({ type: 'user_input', label: 'Dun overdue account', input: { account: '4471' } });
    rec.recordToolCall({ name: 'get_status', arguments: { account: '4471' }, result: { due: 1 } });
    rec.step({ type: 'final_output', label: 'Sent reminder' });
    const run = await rec.end();
    expect(run!.steps.map((s) => s.type)).toEqual(['user_input', 'tool_call', 'final_output']);
    expect(verifyRun(run!).ok).toBe(true);
  });

  it('an empty session ends as null and leaves no journal behind', async () => {
    const rec = startMcpRecording({ dir: home, id: 'mcp-empty' });
    expect(rec.runId).toBe('mcp-empty');
    expect(await rec.end()).toBeNull();
    expect(existsSync(join(home, 'journal'))).toBe(false);
  });

  it('journals each call during the session and cleans up on end', async () => {
    const rec = startMcpRecording({ dir: home, id: 'mcp-j' });
    rec.recordToolCall({ name: 'a', result: { ok: true } });
    const journal = join(home, 'journal', 'mcp-j.jsonl');
    expect(existsSync(journal)).toBe(true);
    await rec.end();
    expect(existsSync(journal)).toBe(false);
    expect(readdirSync(join(home, 'journal'))).toEqual([]);
  });

  it('refuses to record after the session ended', async () => {
    const rec = startMcpRecording({ dir: null });
    rec.recordToolCall({ name: 'a' });
    await rec.end();
    expect(() => rec.recordToolCall({ name: 'b' })).toThrow(/already ended/);
  });
});
