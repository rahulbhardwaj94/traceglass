import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RunStore, ingestAndFinalize, type Run } from '@traceglass/core';
import { buildServer } from './server.js';

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
