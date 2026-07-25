import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import {
  RunStore,
  renderReport,
  verifyRun,
  discoverSessions,
  findSession,
  readSessionRecords,
  ingestAndFinalize,
  ingestClaudeCodeAndFinalize,
  ingestOtel,
  finalizeRun,
  listLiveRecordings,
  findLiveRecording,
  liveRunFromJournal,
  readJournal,
  type Run,
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

export interface ServerOptions {
  /** Bearer token required for all POST routes (and GETs when requireAuthForReads). */
  token?: string;
  /** Register the collector ingest routes (POST /api/ingest, POST /v1/traces). */
  enableIngest?: boolean;
  /** Applied to every ingested run before saving (e.g. Ed25519 signing). */
  signer?: (run: Run) => Run;
  /** Also require the token on GET /api routes (set when binding non-loopback). */
  requireAuthForReads?: boolean;
}

function tokenMatches(header: string | undefined, token: string): boolean {
  if (!header || !header.startsWith('Bearer ')) return false;
  const presented = Buffer.from(header.slice('Bearer '.length));
  const expected = Buffer.from(token);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/**
 * Path used for the authorization decision. Prefer the route Fastify matched —
 * already canonical — and fall back to the decoded pathname so an unrouted
 * request can never slip through undecoded. The router decodes once, so we do
 * too; matching its behaviour exactly is the point.
 */
function authPath(req: FastifyRequest): string {
  const matched = req.routeOptions?.url;
  if (matched) return matched;
  const path = req.url.split('?')[0] ?? '';
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}

/** True when the request targets the JSON API rather than the static SPA. */
function isApiRoute(path: string): boolean {
  return path === '/api' || path.startsWith('/api/');
}

/**
 * Build the Fastify app: JSON API over the run store plus the static web SPA.
 * By default (dashboard mode) the store is read-only from the server's
 * perspective; serve mode adds authenticated collector ingest routes.
 */
export function buildServer(store: RunStore, opts: ServerOptions = {}): FastifyInstance {
  const app = Fastify({ logger: false });

  if (opts.token) {
    const token = opts.token;
    app.addHook('preHandler', async (req: FastifyRequest, reply: FastifyReply) => {
      // Authorize against the route Fastify actually matched, never the raw
      // URL. The router decodes percent-escapes before matching, so a raw
      // string test lets "/%61pi/runs" miss a "/api" prefix check and still
      // reach the /api/runs handler — an unauthenticated read of every run.
      const needsAuth =
        req.method === 'POST' || (opts.requireAuthForReads === true && isApiRoute(authPath(req)));
      if (needsAuth && !tokenMatches(req.headers.authorization, token)) {
        return reply.code(401).send({ error: 'unauthorized' });
      }
    });
  }

  /** Finalized-run save shared by the ingest routes: sign, dedupe, respond. */
  function saveIngested(run: Run): { runId: string; deduped: boolean } {
    if (store.getRun(run.id)) return { runId: run.id, deduped: true };
    const signed = opts.signer ? opts.signer(run) : run;
    store.saveRun(signed);
    return { runId: run.id, deduped: false };
  }

  if (opts.enableIngest) {
    // Generic collector endpoint: native or OTLP/JSON body, auto-detected.
    app.post('/api/ingest', async (req, reply) => {
      try {
        return saveIngested(ingestAndFinalize(req.body));
      } catch (e) {
        return reply.code(400).send({
          error: e instanceof Error ? (e.message.split('\n')[0] ?? e.message) : String(e),
        });
      }
    });

    // OTLP/HTTP-JSON compatibility path (point an OTLP exporter at /v1/traces).
    app.post('/v1/traces', async (req, reply) => {
      try {
        const result = saveIngested(finalizeRun(ingestOtel(req.body)));
        return { partialSuccess: {}, ...result };
      } catch (e) {
        return reply.code(400).send({
          error: e instanceof Error ? (e.message.split('\n')[0] ?? e.message) : String(e),
        });
      }
    });
  }

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

  // Live tail (v0.7): in-progress recordings, reconstructed from their journals.
  app.get('/api/live', async () => listLiveRecordings());

  app.get<{ Params: { id: string } }>('/api/live/:id', async (req, reply) => {
    const live = findLiveRecording(req.params.id);
    if (!live) {
      // Already finalized? Hand back the stored run so the dashboard can
      // seamlessly switch from live view to the sealed record.
      const stored = store.getRun(req.params.id);
      if (stored) return { ...stored, live: false };
      return reply.code(404).send({ error: 'no live recording with that id' });
    }
    try {
      return { ...liveRunFromJournal(readJournal(live.file)), live: true };
    } catch {
      return reply.code(503).send({ error: 'journal is mid-write; retry' });
    }
  });

  // Cross-run step search (v0.4): ?q=<text>&limit=<n>
  app.get<{ Querystring: { q?: string; limit?: string } }>('/api/search', async (req, reply) => {
    const q = (req.query.q ?? '').trim();
    if (!q) return reply.code(400).send({ error: 'missing query parameter q' });
    const limit = req.query.limit ? Number(req.query.limit) : undefined;
    return store.searchRuns(q, {
      limit: limit !== undefined && Number.isFinite(limit) && limit > 0 ? limit : undefined,
    });
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
    if (!store.getRun(run.id)) store.saveRun(opts.signer ? opts.signer(run) : run);
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

function isLoopback(host: string): boolean {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
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

export interface ServeOptions {
  port: number;
  host: string;
  token?: string;
  signer?: (run: Run) => Run;
}

/**
 * Start collector mode: fixed host/port, ingest routes enabled, bearer-token
 * auth on POSTs. Binding a non-loopback host without a token is refused —
 * that is the hard line that keeps "local-first" true when the port is
 * reachable from a network.
 */
export async function startServe(store: RunStore, opts: ServeOptions): Promise<ServerHandle> {
  if (!isLoopback(opts.host) && !opts.token) {
    throw new Error(
      `Refusing to bind ${opts.host} without a token. Pass --token or set TRACEGLASS_TOKEN.`,
    );
  }
  const app = buildServer(store, {
    token: opts.token,
    enableIngest: true,
    signer: opts.signer,
    requireAuthForReads: !isLoopback(opts.host),
  });
  await app.listen({ port: opts.port, host: opts.host });
  return {
    fastify: app,
    port: opts.port,
    url: `http://${opts.host}:${opts.port}`,
    close: () => app.close(),
  };
}
