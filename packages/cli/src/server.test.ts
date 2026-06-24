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
