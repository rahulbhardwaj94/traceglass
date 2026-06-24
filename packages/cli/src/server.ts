import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import Fastify, { type FastifyInstance } from 'fastify';
import fastifyStatic from '@fastify/static';
import {
  RunStore,
  renderReport,
  verifyRun,
  discoverSessions,
  findSession,
  readSessionRecords,
  ingestClaudeCodeAndFinalize,
} from '@traceglass/core';

const require = createRequire(import.meta.url);

/**
 * Locate the built web SPA directory. When published, the dashboard is bundled
 * into this package at dist/web (next to the compiled server). In the workspace
 * we fall back to resolving the sibling @traceglass/web build directly.
 */
function resolveWebDir(): string | null {
  const bundled = join(dirname(fileURLToPath(import.meta.url)), 'web');
  if (existsSync(join(bundled, 'index.html'))) return bundled;
  try {
    const pkg = require.resolve('@traceglass/web/package.json');
    const dir = join(dirname(pkg), 'dist');
    return existsSync(join(dir, 'index.html')) ? dir : null;
  } catch {
    return null;
  }
}

export interface ServerHandle {
  fastify: FastifyInstance;
  url: string;
  port: number;
  close: () => Promise<void>;
}

/**
 * Build the Fastify app: JSON API over the run store plus the static web SPA.
 * The store is read-only from the server's perspective (append-only by design).
 */
export function buildServer(store: RunStore): FastifyInstance {
  const app = Fastify({ logger: false });

  app.get('/api/runs', async () => store.listRuns());

  app.get<{ Params: { id: string } }>('/api/runs/:id', async (req, reply) => {
    const run = store.getRun(req.params.id);
    if (!run) return reply.code(404).send({ error: 'run not found' });
    return run;
  });

  app.get<{ Params: { id: string } }>('/api/runs/:id/verify', async (req, reply) => {
    const run = store.getRun(req.params.id);
    if (!run) return reply.code(404).send({ error: 'run not found' });
    return verifyRun(run);
  });

  app.get<{ Params: { id: string } }>('/api/runs/:id/report', async (req, reply) => {
    const run = store.getRun(req.params.id);
    if (!run) return reply.code(404).send({ error: 'run not found' });
    const html = renderReport(run);
    return reply
      .header('content-type', 'text/html; charset=utf-8')
      .header('content-disposition', `attachment; filename="traceglass-${run.id}.html"`)
      .send(html);
  });

  // Claude Code session discovery + on-demand ingestion (v0.2 session picker).
  app.get('/api/sessions', async () => discoverSessions());

  app.post<{ Params: { id: string } }>('/api/sessions/:id/ingest', async (req, reply) => {
    const session = findSession(req.params.id);
    if (!session) return reply.code(404).send({ error: 'session not found' });
    const run = ingestClaudeCodeAndFinalize(readSessionRecords(session.file), {
      name: session.firstPrompt,
    });
    // The run id is derived from the session log, not the filename — so dedupe
    // by the real id after ingesting (the store is append-only).
    if (!store.getRun(run.id)) store.saveRun(run);
    return { runId: run.id };
  });

  const webDir = resolveWebDir();
  if (webDir) {
    app.register(fastifyStatic, { root: webDir });
    // SPA fallback: serve index.html for any non-API GET.
    app.setNotFoundHandler((req, reply) => {
      if (req.method === 'GET' && !req.url.startsWith('/api')) {
        return reply.sendFile('index.html');
      }
      return reply.code(404).send({ error: 'not found' });
    });
  }

  return app;
}

/** Start the server on an ephemeral free port and return a handle. */
export async function startServer(store: RunStore): Promise<ServerHandle> {
  const app = buildServer(store);
  await app.listen({ port: 0, host: '127.0.0.1' });
  const addr = app.server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('Failed to determine server port');
  }
  const port = addr.port;
  return {
    fastify: app,
    port,
    url: `http://127.0.0.1:${port}`,
    close: () => app.close(),
  };
}
