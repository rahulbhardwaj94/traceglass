import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { Readable } from 'node:stream';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RunStore, ingestAndFinalize, signRun, type Run } from '@traceglass/core';
import { buildServer, type FleetResponse } from './server.js';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../fixtures');
const loopRaw = JSON.parse(readFileSync(join(fixturesDir, 'sample-run-loop.json'), 'utf8'));

let store: RunStore;
let app: ReturnType<typeof buildServer>;
let run: Run;
let sessionsDir: string;

beforeAll(async () => {
  store = new RunStore(':memory:');
  run = ingestAndFinalize(loopRaw);
  store.saveRun(run);

  // Point discovery at a temp sessions dir holding our Claude Code fixture.
  sessionsDir = mkdtempSync(join(tmpdir(), 'tg-sessions-'));
  const projectDir = join(sessionsDir, '-tmp-fixture-project');
  mkdirSync(projectDir, { recursive: true });
  copyFileSync(
    join(fixturesDir, 'sample-claude-code-session.jsonl'),
    join(projectDir, 'sess-fixture.jsonl'),
  );
  process.env.CLAUDE_PROJECTS_DIR = sessionsDir;

  app = buildServer(store);
  await app.ready();
});

afterAll(async () => {
  await app.close();
  store.close();
  rmSync(sessionsDir, { recursive: true, force: true });
  delete process.env.CLAUDE_PROJECTS_DIR;
});

describe('API (acceptance §M3)', () => {
  it('GET /api/runs lists the ingested run', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/runs' });
    expect(res.statusCode).toBe(200);
    const list = res.json() as Array<{ id: string }>;
    expect(list.map((r) => r.id)).toContain(run.id);
  });

  it('GET /api/runs/:id returns the full run with steps', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/runs/${run.id}` });
    expect(res.statusCode).toBe(200);
    const body = res.json() as Run;
    expect(body.steps).toHaveLength(run.steps.length);
    expect(body.runHash).toBe(run.runHash);
  });

  it('GET /api/runs/:id/verify confirms integrity', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/runs/${run.id}/verify` });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { ok: boolean }).ok).toBe(true);
  });

  it('GET /api/runs/:id/report returns standalone HTML with the runHash', async () => {
    const res = await app.inject({ method: 'GET', url: `/api/runs/${run.id}/report` });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('<!doctype html>');
    expect(res.body).toContain(run.runHash);
  });

  it('returns 404 for an unknown run', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/runs/does-not-exist' });
    expect(res.statusCode).toBe(404);
  });
});

describe('Claude Code sessions API (v0.2)', () => {
  it('GET /api/sessions discovers the fixture session', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/sessions' });
    expect(res.statusCode).toBe(200);
    const list = res.json() as Array<{ id: string; messageCount: number; firstPrompt: string }>;
    const found = list.find((s) => s.id === 'sess-fixture');
    expect(found).toBeDefined();
    expect(found!.messageCount).toBeGreaterThan(0);
    expect(found!.firstPrompt).toContain('payment status');
  });

  it('POST /api/sessions/:id/ingest ingests + makes the run retrievable', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/sessions/sess-fixture/ingest' });
    expect(res.statusCode).toBe(200);
    const { runId } = res.json() as { runId: string };
    expect(runId).toBe('cc-sess-abc');

    const got = await app.inject({ method: 'GET', url: `/api/runs/${runId}` });
    expect(got.statusCode).toBe(200);
    expect((got.json() as Run).status).toBe('completed');
  });

  it('ingest is idempotent (re-POST returns the same runId)', async () => {
    const again = await app.inject({ method: 'POST', url: '/api/sessions/sess-fixture/ingest' });
    expect(again.statusCode).toBe(200);
    expect((again.json() as { runId: string }).runId).toBe('cc-sess-abc');
  });

  it('returns 404 for an unknown session', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/sessions/nope/ingest' });
    expect(res.statusCode).toBe(404);
  });
});

describe('search API (v0.4)', () => {
  it('GET /api/search finds steps across runs by payload text', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/search?q=4471' });
    expect(res.statusCode).toBe(200);
    const hits = res.json() as Array<{ runId: string; snippet: string }>;
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.map((h) => h.runId)).toContain(run.id);
    expect(hits[0]!.snippet).toContain('4471');
  });

  it('rejects a missing query with 400 and caps results with limit', async () => {
    expect((await app.inject({ method: 'GET', url: '/api/search' })).statusCode).toBe(400);
    const limited = await app.inject({ method: 'GET', url: '/api/search?q=a&limit=2' });
    expect((limited.json() as unknown[]).length).toBeLessThanOrEqual(2);
  });
});

describe('fleet API (v0.10)', () => {
  // Policy discovery falls back to <TRACEGLASS_HOME>/policy.json, so point HOME
  // at an empty temp dir — otherwise the developer's own policy file decides
  // whether these assertions hold.
  let policyHome: string;
  let priorHome: string | undefined;
  beforeAll(() => {
    priorHome = process.env.TRACEGLASS_HOME;
    policyHome = mkdtempSync(join(tmpdir(), 'tg-fleet-home-'));
    process.env.TRACEGLASS_HOME = policyHome;
  });
  afterAll(() => {
    if (priorHome === undefined) delete process.env.TRACEGLASS_HOME;
    else process.env.TRACEGLASS_HOME = priorHome;
    rmSync(policyHome, { recursive: true, force: true });
  });

  /** A store holding: the loop fixture, a signed run, and a tampered run. */
  async function fleetApp(opts: Parameters<typeof buildServer>[1] = {}) {
    const s = new RunStore(':memory:');
    s.saveRun(run);

    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const clean = ingestAndFinalize({
      id: 'fleet-clean',
      name: 'clean signed agent',
      currency: 'USD',
      steps: [
        {
          type: 'tool_call',
          toolName: 'payments.refund',
          label: 'Tool: payments.refund',
          startedAt: '2026-01-01T00:00:00.000Z',
          durationMs: 5,
          cost: 0.25,
          tokens: 100,
        },
      ],
    });
    s.saveRun(
      signRun(
        clean,
        privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      ),
    );

    // A run whose stored bytes no longer match its own hash chain.
    const honest = ingestAndFinalize({
      id: 'fleet-tampered',
      name: 'rewritten history',
      currency: 'USD',
      steps: [
        {
          type: 'tool_call',
          toolName: 'get_status',
          label: 'Tool: get_status',
          startedAt: '2026-01-01T00:00:00.000Z',
          durationMs: 5,
          output: { status: 'overdue' },
        },
      ],
    });
    s.saveRun({
      ...honest,
      steps: [{ ...honest.steps[0]!, output: { status: 'paid' } }],
    });

    const a = buildServer(s, opts);
    await a.ready();
    return { s, a };
  }

  it('GET /api/fleet rolls every stored run up for triage', async () => {
    const { s, a } = await fleetApp();
    try {
      const res = await a.inject({ method: 'GET', url: '/api/fleet' });
      expect(res.statusCode).toBe(200);
      const body = res.json() as FleetResponse;
      const byId = new Map(body.runs.map((r) => [r.id, r]));
      expect(byId.size).toBe(3);

      // The loop fixture carries warnings — the whole point of the list.
      const loop = byId.get(run.id)!;
      expect(loop.warnings.total).toBe(run.warnings.length);
      expect(loop.warnings.loop).toBeGreaterThan(0);
      expect(loop.warningMessages.length).toBe(run.warnings.length);
      expect(loop.steps).toBe(run.totals.steps);
      expect(loop.signed).toBe(false);
      expect(loop.chainOk).toBe(true);

      const clean = byId.get('fleet-clean')!;
      expect(clean.signed).toBe(true);
      expect(clean.keyId).toMatch(/^[0-9a-f]{16}$/);
      expect(clean.signatureOk).toBe(true);
      expect(clean.warnings.total).toBe(0);

      const tampered = byId.get('fleet-tampered')!;
      expect(tampered.chainOk).toBe(false);
      expect(tampered.integrityMessage).toMatch(/step/i);

      // No policy configured → scoring is null, not a fabricated pass.
      expect(body.policy.configured).toBe(false);
      expect(body.runs.every((r) => r.policyOk === null)).toBe(true);
    } finally {
      await a.close();
      s.close();
    }
  });

  it('scores every run against a configured policy', async () => {
    const { s, a } = await fleetApp({
      policy: { name: 'no refunds', rules: { forbidTools: ['payments.*'], requireSignature: true } },
    });
    try {
      const body = (await a.inject({ method: 'GET', url: '/api/fleet' })).json() as FleetResponse;
      expect(body.policy).toMatchObject({ configured: true, name: 'no refunds', source: 'inline' });

      const clean = body.runs.find((r) => r.id === 'fleet-clean')!;
      expect(clean.policyOk).toBe(false);
      expect(clean.policyViolations.map((v) => v.rule)).toContain('forbidTools');

      // The unsigned fixture trips requireSignature instead.
      const loop = body.runs.find((r) => r.id === run.id)!;
      expect(loop.policyOk).toBe(false);
      expect(loop.policyViolations.map((v) => v.rule)).toContain('requireSignature');
    } finally {
      await a.close();
      s.close();
    }
  });

  it('serves a repeat request from cache without changing the answer', async () => {
    const { s, a } = await fleetApp();
    try {
      const first = (await a.inject({ method: 'GET', url: '/api/fleet' })).json() as FleetResponse;
      const second = (await a.inject({ method: 'GET', url: '/api/fleet' })).json() as FleetResponse;
      expect(second.runs).toEqual(first.runs);
    } finally {
      await a.close();
      s.close();
    }
  });

  it('reports a broken policy file instead of silently passing every run', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tg-policy-'));
    const file = join(dir, 'policy.json');
    writeFileSync(file, '{ not json');
    process.env.TRACEGLASS_POLICY = file;
    try {
      const { s, a } = await fleetApp();
      try {
        const body = (await a.inject({ method: 'GET', url: '/api/fleet' })).json() as FleetResponse;
        expect(body.policy.configured).toBe(true);
        expect(body.policy.error).toMatch(/Could not read policy/);
        expect(body.runs.every((r) => r.policyOk === null)).toBe(true);
      } finally {
        await a.close();
        s.close();
      }
    } finally {
      delete process.env.TRACEGLASS_POLICY;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('is a read route: the fleet never exposes a write path', async () => {
    const { s, a } = await fleetApp();
    try {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE'] as const) {
        const res = await a.inject({ method, url: '/api/fleet' });
        expect(res.statusCode).toBe(404);
      }
    } finally {
      await a.close();
      s.close();
    }
  });
});

describe('live tail API (v0.7)', () => {
  it('GET /api/live lists in-progress recordings', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/live' });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json())).toBe(true);
  });

  it('GET /api/live/:id falls back to the stored run once finalized', async () => {
    // No journal exists for this id, but it IS stored — the dashboard should
    // seamlessly switch from live view to the sealed record.
    const res = await app.inject({ method: 'GET', url: `/api/live/${run.id}` });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { live: boolean; runHash: string };
    expect(body.live).toBe(false);
    expect(body.runHash).toBe(run.runHash);
  });

  it('GET /api/live/:id 404s for an id that is neither live nor stored', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/live/ghost-run' });
    expect(res.statusCode).toBe(404);
  });
});

describe('serve mode: token auth + collector ingest (v0.3)', () => {
  const nativeBody = JSON.parse(
    readFileSync(join(fixturesDir, 'sample-run-native.json'), 'utf8'),
  ) as { id: string };

  async function collectorApp() {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 's3cret', enableIngest: true });
    await a.ready();
    return { s, a };
  }

  it('POST /api/ingest with the right token ingests and returns the runId', async () => {
    const { s, a } = await collectorApp();
    const res = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer s3cret', 'content-type': 'application/json' },
      payload: nativeBody,
    });
    expect(res.statusCode).toBe(200);
    const { runId, deduped } = res.json() as { runId: string; deduped: boolean };
    expect(runId).toBe(nativeBody.id);
    expect(deduped).toBe(false);
    expect(s.getRun(runId)).not.toBeNull();

    // Re-POST dedupes instead of failing on the append-only store.
    const again = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer s3cret', 'content-type': 'application/json' },
      payload: nativeBody,
    });
    expect((again.json() as { deduped: boolean }).deduped).toBe(true);
    await a.close();
    s.close();
  });

  it('rejects a wrong or missing token with 401', async () => {
    const { s, a } = await collectorApp();
    const wrong = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer nope', 'content-type': 'application/json' },
      payload: nativeBody,
    });
    expect(wrong.statusCode).toBe(401);
    const missing = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { 'content-type': 'application/json' },
      payload: nativeBody,
    });
    expect(missing.statusCode).toBe(401);
    await a.close();
    s.close();
  });

  it('GET routes stay tokenless in loopback serve mode', async () => {
    const { s, a } = await collectorApp();
    const res = await a.inject({ method: 'GET', url: '/api/runs' });
    expect(res.statusCode).toBe(200);
    await a.close();
    s.close();
  });

  it('requireAuthForReads gates GET /api routes too', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, requireAuthForReads: true });
    await a.ready();
    expect((await a.inject({ method: 'GET', url: '/api/runs' })).statusCode).toBe(401);
    expect(
      (
        await a.inject({
          method: 'GET',
          url: '/api/runs',
          headers: { authorization: 'Bearer t' },
        })
      ).statusCode,
    ).toBe(200);
    await a.close();
    s.close();
  });

  it('requireAuthForReads cannot be bypassed with a non-canonical URL', async () => {
    // The router decodes percent-escapes before matching, so "/%61pi/runs"
    // reaches the /api/runs handler. A gate that string-matched req.url served
    // every stored run to an anonymous caller.
    const s = new RunStore(':memory:');
    s.saveRun(run);
    const a = buildServer(s, { token: 't', enableIngest: true, requireAuthForReads: true });
    await a.ready();

    const authorized = await a.inject({
      method: 'GET',
      url: '/api/runs',
      headers: { authorization: 'Bearer t' },
    });
    expect(authorized.statusCode).toBe(200);
    expect(authorized.body).toContain(run.id);

    for (const url of ['/api/runs', '/%61pi/runs', '/api/%72uns', `/api/runs/${run.id}`]) {
      const res = await a.inject({ method: 'GET', url });
      expect(res.statusCode, `${url} must not serve run data anonymously`).toBe(401);
      expect(res.body).not.toContain(run.runHash);
    }
    await a.close();
    s.close();
  });

  it('POST /v1/traces accepts an OTLP/JSON export', async () => {
    const { s, a } = await collectorApp();
    const otelBody = JSON.parse(readFileSync(join(fixturesDir, 'sample-run-otel.json'), 'utf8'));
    const res = await a.inject({
      method: 'POST',
      url: '/v1/traces',
      headers: { authorization: 'Bearer s3cret', 'content-type': 'application/json' },
      payload: otelBody,
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { partialSuccess: object; runId: string };
    expect(body.partialSuccess).toEqual({});
    expect(s.getRun(body.runId)).not.toBeNull();
    await a.close();
    s.close();
  });

  it('rejects an unparseable body with 400, not a crash', async () => {
    const { s, a } = await collectorApp();
    const res = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer s3cret', 'content-type': 'application/json' },
      payload: { nonsense: true },
    });
    expect(res.statusCode).toBe(400);
    await a.close();
    s.close();
  });

  it('an oversized body is rejected with 413 naming the limit and the flag', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, bodyLimit: 2048 });
    await a.ready();

    const tooBig = { id: 'x', name: 'x', steps: [], filler: 'a'.repeat(4096) };
    const res = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer t', 'content-type': 'application/json' },
      payload: tooBig,
    });
    expect(res.statusCode).toBe(413);
    const body = res.json() as { error: string; message: string; limitBytes: number };
    expect(body.error).toBe('payload too large');
    expect(body.message).toContain('--body-limit');
    expect(body.limitBytes).toBe(2048);

    // A body inside the limit is unaffected (this one fails validation, at 400).
    const small = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer t', 'content-type': 'application/json' },
      payload: { nonsense: true },
    });
    expect(small.statusCode).toBe(400);
    await a.close();
    s.close();
  });

  it('a body with no declared length still hits the parser backstop (413)', async () => {
    // Chunked uploads carry no content-length, so the cheap early check cannot
    // see them coming. Fastify's own bodyLimit has to catch these.
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, bodyLimit: 2048 });
    await a.ready();

    const chunked = Readable.from([
      Buffer.from('{"pad":"'),
      Buffer.from('a'.repeat(8192)),
      Buffer.from('"}'),
    ]);
    const res = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: {
        authorization: 'Bearer t',
        'content-type': 'application/json',
        'transfer-encoding': 'chunked',
      },
      payload: chunked,
    });
    expect(res.statusCode).toBe(413);
    expect((res.json() as { error: string }).error).toBe('payload too large');
    await a.close();
    s.close();
  });

  it('floods the ingest routes get 429 with retry-after; reads are untouched', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, rateLimit: 3 });
    await a.ready();

    const post = () =>
      a.inject({
        method: 'POST',
        url: '/api/ingest',
        headers: { authorization: 'Bearer t', 'content-type': 'application/json' },
        payload: nativeBody,
      });

    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await post()).statusCode);
    expect(codes.slice(0, 3).every((c) => c === 200)).toBe(true);
    expect(codes.slice(3)).toEqual([429, 429]);

    const limited = await post();
    expect(limited.statusCode).toBe(429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    expect(limited.headers['x-ratelimit-limit']).toBe('3');
    const body = limited.json() as { error: string; message: string; limit: number };
    expect(body.error).toBe('too many requests');
    expect(body.message).toContain('3 requests per minute');

    // GET routes are not rate limited — a throttled collector must not blind
    // the dashboard someone is using to look at the runs already stored.
    for (let i = 0; i < 10; i++) {
      expect((await a.inject({ method: 'GET', url: '/api/runs' })).statusCode).toBe(200);
    }
    await a.close();
    s.close();
  });

  it('rate limiting keys off the matched route, so an encoded path cannot dodge it', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, rateLimit: 2 });
    await a.ready();
    const send = (url: string) =>
      a.inject({
        method: 'POST',
        url,
        headers: { authorization: 'Bearer t', 'content-type': 'application/json' },
        payload: nativeBody,
      });
    await send('/api/ingest');
    await send('/api/ingest');
    // "/%61pi/ingest" routes to the same handler; it must land in the same bucket.
    expect((await send('/%61pi/ingest')).statusCode).toBe(429);
    await a.close();
    s.close();
  });

  it('rateLimit: 0 disables the limiter entirely', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, rateLimit: 0 });
    await a.ready();
    for (let i = 0; i < 12; i++) {
      const res = await a.inject({
        method: 'POST',
        url: '/api/ingest',
        headers: { authorization: 'Bearer t', 'content-type': 'application/json' },
        payload: nativeBody,
      });
      expect(res.statusCode).toBe(200);
    }
    await a.close();
    s.close();
  });

  it('the limiter does not weaken auth: a tokenless POST is still 401', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, { token: 't', enableIngest: true, rateLimit: 100 });
    await a.ready();
    expect(
      (
        await a.inject({
          method: 'POST',
          url: '/api/ingest',
          headers: { 'content-type': 'application/json' },
          payload: nativeBody,
        })
      ).statusCode,
    ).toBe(401);
    await a.close();
    s.close();
  });

  it('signer hook is applied to ingested runs', async () => {
    const s = new RunStore(':memory:');
    const a = buildServer(s, {
      token: 't',
      enableIngest: true,
      signer: (r) => ({ ...r, name: `${r.name} [signed]` }),
    });
    await a.ready();
    const res = await a.inject({
      method: 'POST',
      url: '/api/ingest',
      headers: { authorization: 'Bearer t', 'content-type': 'application/json' },
      payload: nativeBody,
    });
    const { runId } = res.json() as { runId: string };
    expect(s.getRun(runId)!.name).toContain('[signed]');
    await a.close();
    s.close();
  });
});
