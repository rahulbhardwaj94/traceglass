import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RunStore, type Run } from '@traceglass/core';
import { buildServer } from './server.js';

/**
 * ADVERSARIAL SUITE — collector ingest (attack 9).
 *
 * The collector is the only network-reachable WRITE surface. An authenticated
 * but hostile client must not be able to crash it, hang it, or corrupt the
 * append-only store. Every case here asserts a clean, bounded outcome — a
 * status code and a fast return — rather than "it worked".
 */

const TOKEN = 'ingest-token';
const H = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };

let store: RunStore;
let app: ReturnType<typeof buildServer>;

beforeAll(async () => {
  store = new RunStore(':memory:');
  app = buildServer(store, { token: TOKEN, enableIngest: true });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  store.close();
});

function nativeStep(i: number, extra: Record<string, unknown> = {}) {
  return {
    type: 'user_input',
    label: `step ${i}`,
    startedAt: new Date(Date.UTC(2026, 0, 1) + i).toISOString(),
    durationMs: 1,
    ...extra,
  };
}

async function post(payload: unknown, url = '/api/ingest') {
  const started = Date.now();
  const res = await app.inject({ method: 'POST', url, headers: H, payload: payload as never });
  return { status: res.statusCode, body: res.body, ms: Date.now() - started };
}

/**
 * The oversize cases run against an app with an explicit small bodyLimit.
 * v0.8 raised the default to 32 MiB (Fastify's 1 MB default silently rejected
 * legitimate traces), and generating a >32 MiB body per assertion would make
 * this suite slow for no extra coverage. What matters is that the CONFIGURED
 * limit is enforced, whatever it is set to.
 */
const SMALL_LIMIT = 1024 * 1024;
let smallStore: RunStore;
let smallApp: ReturnType<typeof buildServer>;

beforeAll(async () => {
  smallStore = new RunStore(':memory:');
  smallApp = buildServer(smallStore, {
    token: TOKEN,
    enableIngest: true,
    bodyLimit: SMALL_LIMIT,
  });
  await smallApp.ready();
});

afterAll(async () => {
  await smallApp.close();
  smallStore.close();
});

async function postSmall(payload: unknown, url = '/api/ingest') {
  const started = Date.now();
  const res = await smallApp.inject({
    method: 'POST',
    url,
    headers: H,
    payload: payload as never,
  });
  return { status: res.statusCode, body: res.body, ms: Date.now() - started };
}

describe('ATTACK 9a: oversized bodies', () => {
  it('a payload over the configured limit is rejected with 413, not stored', async () => {
    const res = await postSmall({
      id: 'oversized',
      name: 'x',
      currency: 'USD',
      steps: [nativeStep(0, { input: 'A'.repeat(2 * SMALL_LIMIT) })],
    });
    expect(res.status).toBe(413);
    expect(res.ms).toBeLessThan(3000);
    expect(smallStore.getRun('oversized')).toBeNull();
  });

  it('~10^5 steps exceeds the body limit and is refused before any parsing work', async () => {
    const steps = Array.from({ length: 100_000 }, (_, i) => nativeStep(i));
    const res = await postSmall({ id: 'stepbomb', name: 'x', currency: 'USD', steps });
    expect(res.status).toBe(413);
    expect(res.ms).toBeLessThan(5000);
    expect(smallStore.getRun('stepbomb')).toBeNull();
  });

  it('the 32 MiB default accepts a multi-MB trace that the old 1 MB default refused', async () => {
    // The v0.8 default exists because real Claude Code sessions with tool
    // outputs run to several MB; under Fastify's default they 413'd silently.
    const res = await post({
      id: 'big-but-legal',
      name: 'x',
      currency: 'USD',
      steps: [nativeStep(0, { input: 'A'.repeat(2 * 1024 * 1024) })],
    });
    expect(res.status).toBe(200);
    expect(store.getRun('big-but-legal')).not.toBeNull();
  });

  it('a large-but-legal run (5k steps, under the limit) still ingests promptly', async () => {
    // The bound must be the BODY SIZE, not an arbitrary refusal — otherwise the
    // 413s above would prove nothing about the collector's robustness.
    const steps = Array.from({ length: 5000 }, (_, i) => nativeStep(i));
    const res = await post({ id: 'legal-5k', name: 'x', currency: 'USD', steps });
    expect(res.status).toBe(200);
    expect(res.ms).toBeLessThan(5000);
    expect(store.getRun('legal-5k')!.totals.steps).toBe(5000);
  });

  it('the same limit applies to the OTLP path', async () => {
    const res = await postSmall(
      {
        resourceSpans: [
          {
            scopeSpans: [
              {
                spans: [
                  {
                    traceId: 'a'.repeat(32),
                    spanId: 'b'.repeat(16),
                    name: 'A'.repeat(2 * SMALL_LIMIT),
                    startTimeUnixNano: '1767225600000000000',
                    endTimeUnixNano: '1767225601000000000',
                  },
                ],
              },
            ],
          },
        ],
      },
      '/v1/traces',
    );
    expect(res.status).toBe(413);
  });
});

/**
 * Build the ingest body as a RAW JSON STRING. Handing `app.inject` a deep JS
 * object makes the test harness recurse while serializing, which would blow the
 * stack on the client side and prove nothing about the server. The attacker
 * controls bytes on the wire, so bytes on the wire is what we send.
 */
function deepBody(id: string, open: string, close: string, depth: number): string {
  return (
    `{"id":${JSON.stringify(id)},"name":"x","currency":"USD","steps":[` +
    `{"type":"user_input","label":"l","startedAt":"2026-01-01T00:00:00.000Z","durationMs":1,` +
    `"input":${open.repeat(depth)}"leaf"${close.repeat(depth)}}]}`
  );
}

describe('ATTACK 9b: deeply nested payloads', () => {
  it('a 20k-deep nested array returns 4xx, not a process crash', async () => {
    // canonicalize()/sortValue() recurse per level. Blowing the stack must
    // surface as a rejected request, never as an unhandled crash that takes the
    // collector down for every other client.
    const res = await post(deepBody('deep-array', '[', ']', 20_000));
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(res.ms).toBeLessThan(10_000);
    expect(store.getRun('deep-array')).toBeNull();

    // The server is still alive and serving afterwards.
    const alive = await app.inject({ method: 'GET', url: '/api/runs' });
    expect(alive.statusCode).toBe(200);
  });

  it('a 50k-deep nested object also fails closed', async () => {
    const res = await post(deepBody('deep-object', '{"n":', '}', 50_000));
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
    expect(store.getRun('deep-object')).toBeNull();
    expect((await app.inject({ method: 'GET', url: '/api/runs' })).statusCode).toBe(200);
  });

  it('VULNERABILITY: moderate nesting (5k deep) is accepted and stored unbounded', async () => {
    /*
     * VULNERABILITY: there is no depth limit anywhere in the ingest path. A
     * 5,000-level nested payload is accepted, hashed, and written to the store.
     * It only fails when it happens to exceed the V8 stack, which depends on
     * the runtime's stack size — so the SAME payload can be accepted by one
     * deployment and crash-then-400 on another.
     *
     * REAL-WORLD CONSEQUENCE: every later reader of that run (verify, report,
     * export, the dashboard, `searchRuns`) re-walks the structure recursively.
     * A payload that ingested successfully on a machine with a large stack can
     * make `traceglass verify` blow up on the auditor's machine — evidence
     * that cannot be read is evidence that does not exist.
     *
     * WHAT SHOULD HAPPEN: enforce an explicit maximum payload depth at ingest
     * and reject beyond it, so acceptance is deterministic across runtimes.
     */
    const res = await post(deepBody('deep-accepted', '{"n":', '}', 400));
    expect(res.status).toBe(200); // <-- pinning the hole
    expect(store.getRun('deep-accepted')).not.toBeNull();
  });
});

describe('ATTACK 9c: duplicate and conflicting run ids', () => {
  it('VULNERABILITY: a conflicting re-POST is silently deduped and reported as success', async () => {
    /*
     * The append-only guarantee HOLDS: the second body does not overwrite the
     * first. But the response is `200 {deduped: true}` and the conflicting
     * content is discarded without a word.
     *
     * VULNERABILITY: an attacker who can predict or read a run id — they are
     * derived from session logs and SDK timestamps, not secrets — can
     * pre-register that id with an empty run. The genuine agent then POSTs its
     * real evidence, receives HTTP 200, and believes the run was recorded. It
     * was not. Nothing anywhere reports the conflict.
     *
     * REAL-WORLD CONSEQUENCE: silent, targeted evidence suppression that looks
     * exactly like a successful ingest from the client's side.
     *
     * WHAT SHOULD HAPPEN: compare the incoming runHash against the stored one.
     * Identical -> 200 deduped (genuine retry). Different -> 409 Conflict, and
     * an audit-log entry.
     */
    const genuine = {
      id: 'contested',
      name: 'genuine evidence',
      currency: 'USD',
      steps: [nativeStep(0, { input: { transferred: 500000 } })],
    };
    const attacker = {
      id: 'contested',
      name: 'ATTACKER PLACEHOLDER',
      currency: 'USD',
      steps: [nativeStep(0, { input: { nothing: 'to see' } })],
    };

    // The attacker gets there first.
    const first = await post(attacker);
    expect(first.status).toBe(200);
    expect(JSON.parse(first.body).deduped).toBe(false);

    // The genuine agent POSTs and is told everything is fine.
    const second = await post(genuine);
    expect(second.status).toBe(200); // <-- THE HOLE: not 409
    expect(JSON.parse(second.body).deduped).toBe(true);

    // ...but the real evidence was never stored.
    const stored = store.getRun('contested') as Run;
    expect(stored.name).toBe('ATTACKER PLACEHOLDER');
    expect(JSON.stringify(stored)).not.toContain('500000');
  });

  it('an identical re-POST is a genuine idempotent retry (the case dedupe exists for)', async () => {
    const body = {
      id: 'retry',
      name: 'x',
      currency: 'USD',
      steps: [nativeStep(0, { input: { a: 1 } })],
    };
    expect(JSON.parse((await post(body)).body).deduped).toBe(false);
    expect(JSON.parse((await post(body)).body).deduped).toBe(true);
    expect(store.getRun('retry')!.name).toBe('x');
  });

  it('dedupe does not let a hostile body reach the append-only store', async () => {
    // The store's own INSERT-only guard is the backstop under the dedupe check.
    const run = store.getRun('contested')!;
    expect(() => store.saveRun({ ...run, name: 'overwritten' })).toThrow(/append-only/);
    expect(store.getRun('contested')!.name).toBe('ATTACKER PLACEHOLDER');
  });
});

describe('ATTACK 9d: malformed and hostile bodies', () => {
  const cases: Array<[string, unknown, number[]]> = [
    ['null body', null, [400]],
    ['bare array', [1, 2, 3], [400]],
    ['bare string', 'hello', [400]],
    ['bare number', 42, [400]],
    ['empty object', {}, [400]],
    ['steps not an array', { id: 'x', name: 'x', steps: 'nope' }, [400]],
    ['missing id', { name: 'x', steps: [] }, [400]],
    ['empty-string id', { id: '', name: 'x', steps: [] }, [400]],
    ['negative durationMs', { id: 'neg', name: 'x', steps: [nativeStep(0, { durationMs: -1 })] }, [400]],
    ['negative cost', { id: 'negc', name: 'x', steps: [nativeStep(0, { cost: -1e9 })] }, [400]],
    ['NaN-ish duration', { id: 'nan', name: 'x', steps: [nativeStep(0, { durationMs: 'NaN' })] }, [400]],
    ['unknown step type', { id: 'ut', name: 'x', steps: [nativeStep(0, { type: 'sudo' })] }, [400]],
    ['unparseable startedAt', { id: 'bd', name: 'x', steps: [nativeStep(0, { startedAt: 'not-a-date' })] }, [400, 200]],
    ['id with newlines', { id: 'a\nb\rc', name: 'x', steps: [nativeStep(0)] }, [200]],
    ['1MB-ish unicode id', { id: '𝕏'.repeat(1000), name: 'x', steps: [nativeStep(0)] }, [200]],
  ];

  it.each(cases)('%s is handled cleanly', async (_name, payload, allowed) => {
    const res = await post(payload);
    expect(allowed).toContain(res.status);
    expect(res.ms).toBeLessThan(5000);
    expect(res.status).not.toBe(500);
  });

  it('a prototype-pollution attempt does not pollute Object.prototype', async () => {
    await post(
      JSON.parse(
        '{"id":"proto","name":"x","currency":"USD","steps":[],"__proto__":{"polluted":"yes"}}',
      ),
    );
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect((Object.prototype as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('a constructor/prototype key inside a step payload is inert', async () => {
    await post(
      JSON.parse(
        '{"id":"proto2","name":"x","currency":"USD","steps":[{"type":"user_input","label":"l","startedAt":"2026-01-01T00:00:00.000Z","durationMs":1,"input":{"constructor":{"prototype":{"x":1}},"__proto__":{"y":2}}}]}',
      ),
    );
    expect(({} as Record<string, unknown>).y).toBeUndefined();
    const stored = store.getRun('proto2');
    if (stored) expect(Object.getPrototypeOf(stored.steps[0]!.input)).toBe(Object.prototype);
  });

  it('a zero-step run is accepted and produces an empty anchor', async () => {
    // Pinning current behaviour: an empty run IS storable, and its runHash is
    // the empty string. Combined with anchoring, this means "a run that proves
    // nothing" is a representable, verifiable record.
    const res = await post({ id: 'zero-steps', name: 'x', currency: 'USD', steps: [] });
    expect(res.status).toBe(200);
    const stored = store.getRun('zero-steps')!;
    expect(stored.steps).toHaveLength(0);
    expect(stored.runHash).toBe('');
  });

  it('a burst of hostile requests leaves the collector responsive', async () => {
    const hostile = Array.from({ length: 40 }, (_, i) =>
      post({ id: `burst-${i}`, name: 'x', steps: 'not-an-array' }),
    );
    const results = await Promise.all(hostile);
    expect(results.every((r) => r.status === 400)).toBe(true);
    const alive = await app.inject({ method: 'GET', url: '/api/runs' });
    expect(alive.statusCode).toBe(200);
  });

  it('error bodies do not echo back a stack trace or internal paths', async () => {
    const res = await post({ id: 'x', name: 'x', steps: 'nope' });
    expect(res.body).not.toMatch(/\/Users\/|\/home\/|node_modules|at Object\./);
    expect(res.body.split('\n')).toHaveLength(1); // messages are single-line by design
  });
});
