import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import {
  RunStore,
  renderReport,
  verifyRun,
  verifyRunFull,
  evaluatePolicy,
  parsePolicy,
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
  type Policy,
  type Run,
  type RunSummary,
  type WarningKind,
} from '@traceglass/core';
import { dataDir } from './paths.js';

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
 * Largest accepted request body, in bytes (32 MiB).
 *
 * Fastify's 1 MB default is far too small for this workload: a long Claude Code
 * session with tool outputs serialises to several MB, and an OTLP exporter
 * batching a whole agent run routinely pushes past 10 MB. At 1 MB a legitimate
 * trace fails at the parser with no explanation of what went wrong. 32 MiB
 * clears real traces with headroom while still capping a single request at a
 * size the process can buffer without being pushed over. Override with
 * --body-limit / TRACEGLASS_BODY_LIMIT when a fleet genuinely needs more.
 */
export const DEFAULT_BODY_LIMIT = 32 * 1024 * 1024;

/**
 * Ingest requests allowed per IP per minute (default).
 *
 * A collector receiving finished runs is low-rate by nature — an agent that
 * takes minutes to run posts once. 120/min leaves 2/s of sustained headroom for
 * a burst of backfilled runs while stopping one client from pinning the process
 * with an unbounded POST loop. Override with --rate-limit / TRACEGLASS_RATE_LIMIT.
 */
export const DEFAULT_RATE_LIMIT = 120;

const RATE_WINDOW_MS = 60_000;

/**
 * Routes that accept trace data. These are the DoS surface: they parse an
 * attacker-sized body and write to the store. Matched against the route
 * Fastify resolved, never the raw URL — same rule as the auth gate.
 */
const INGEST_ROUTES = new Set(['/api/ingest', '/v1/traces', '/api/sessions/:id/ingest']);

/**
 * Fixed-window per-IP counter for the ingest routes.
 *
 * Deliberately in-process rather than @fastify/rate-limit: the need is one
 * fixed window over three routes, and traceglass ships four production
 * dependencies precisely because it asks people to trust its supply chain with
 * an audit record. Thirty lines we can read beats three transitive packages.
 * The consequence is honest and documented — the window is per process, so a
 * horizontally scaled deployment limits per instance, and state resets on
 * restart. For a local-first collector that is the right trade.
 */
class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  /** Cap on tracked clients, so the limiter itself cannot be a memory sink. */
  private static readonly MAX_KEYS = 10_000;

  constructor(private readonly limit: number) {}

  /** Record a hit; returns whether it is allowed and when the window resets. */
  take(key: string, now = Date.now()): { allowed: boolean; remaining: number; resetAt: number } {
    const existing = this.hits.get(key);
    if (!existing || existing.resetAt <= now) {
      if (this.hits.size >= RateLimiter.MAX_KEYS) this.evictExpired(now);
      const fresh = { count: 1, resetAt: now + RATE_WINDOW_MS };
      this.hits.set(key, fresh);
      return { allowed: true, remaining: this.limit - 1, resetAt: fresh.resetAt };
    }
    existing.count += 1;
    return {
      allowed: existing.count <= this.limit,
      remaining: Math.max(0, this.limit - existing.count),
      resetAt: existing.resetAt,
    };
  }

  private evictExpired(now: number): void {
    for (const [key, entry] of this.hits) {
      if (entry.resetAt <= now) this.hits.delete(key);
    }
    // Still full of live windows: drop the oldest so memory stays bounded.
    if (this.hits.size >= RateLimiter.MAX_KEYS) {
      const oldest = this.hits.keys().next();
      if (!oldest.done) this.hits.delete(oldest.value);
    }
  }
}

/* ── fleet rollup (v0.10) ──────────────────────────────────────────────────── */

/** Per-kind warning tally for one run. */
export interface FleetWarnings {
  loop: number;
  high_cost_step: number;
  error: number;
  total: number;
}

/**
 * One row of the fleet view: everything needed to triage a run WITHOUT loading
 * it. `listRuns` alone cannot answer "which of these went wrong?" — it carries
 * no warnings, no signature, no integrity verdict — and asking the browser to
 * fetch every full run to find out would ship megabytes of step payloads to
 * render a list. So the rollup is computed here, over the same append-only
 * store, and stays strictly read-only.
 */
export interface FleetRun {
  id: string;
  name: string;
  startedAt: string;
  endedAt: string;
  ingestedAt: string;
  status: Run['status'];
  currency: string;
  steps: number;
  tokens: number;
  cost: number;
  durationMs: number;
  runHash: string;
  warnings: FleetWarnings;
  /** Warning messages, in run order — the row subtitle in the dashboard. */
  warningMessages: string[];
  signed: boolean;
  keyId: string | null;
  /** Hash chain recomputed and matched. */
  chainOk: boolean;
  /** Signature (when present) validates against its embedded public key. */
  signatureOk: boolean;
  /** Human-readable verdict for whichever of the two failed, else chain's. */
  integrityMessage: string;
  /** null when no policy is configured on this server. */
  policyOk: boolean | null;
  policyViolations: Array<{ rule: string; message: string }>;
}

/** Where the server's guardrail policy came from, and whether it loaded. */
export interface FleetPolicyInfo {
  configured: boolean;
  name: string | null;
  /** 'inline' (programmatic), 'env' (TRACEGLASS_POLICY), 'home' (~/.traceglass/policy.json). */
  source: 'inline' | 'env' | 'home' | null;
  error: string | null;
}

export interface FleetResponse {
  runs: FleetRun[];
  policy: FleetPolicyInfo;
  generatedAt: string;
}

const WARNING_KINDS: readonly WarningKind[] = ['loop', 'high_cost_step', 'error'];

/**
 * Resolve the guardrail policy the fleet view scores runs against.
 *
 * `traceglass check --policy` is per-invocation, but a fleet dashboard needs a
 * standing answer to "is this run allowed?", so the server takes one policy for
 * its lifetime: passed in programmatically, or pointed at by TRACEGLASS_POLICY,
 * or the conventional ~/.traceglass/policy.json. A broken policy file is
 * reported to the client rather than thrown — the fleet list is still useful
 * without policy scoring, and silently showing every run as compliant because
 * the file had a typo would be the worst of the three outcomes.
 */
function resolvePolicy(inline?: Policy): { policy: Policy | null; info: FleetPolicyInfo } {
  const none: FleetPolicyInfo = { configured: false, name: null, source: null, error: null };
  if (inline) {
    return {
      policy: inline,
      info: { configured: true, name: inline.name ?? null, source: 'inline', error: null },
    };
  }
  const fromEnv = process.env.TRACEGLASS_POLICY;
  const candidates: Array<{ file: string; source: 'env' | 'home'; required: boolean }> = [
    ...(fromEnv ? [{ file: fromEnv, source: 'env' as const, required: true }] : []),
    { file: join(dataDir(), 'policy.json'), source: 'home' as const, required: false },
  ];
  for (const candidate of candidates) {
    if (!existsSync(candidate.file)) {
      if (!candidate.required) continue;
      return {
        policy: null,
        info: {
          ...none,
          configured: true,
          source: candidate.source,
          error: `TRACEGLASS_POLICY points at ${candidate.file}, which does not exist.`,
        },
      };
    }
    try {
      const policy = parsePolicy(JSON.parse(readFileSync(candidate.file, 'utf8')));
      return {
        policy,
        info: { configured: true, name: policy.name ?? null, source: candidate.source, error: null },
      };
    } catch (e) {
      return {
        policy: null,
        info: {
          ...none,
          configured: true,
          source: candidate.source,
          error: `Could not read policy ${candidate.file}: ${
            e instanceof Error ? (e.message.split('\n')[0] ?? e.message) : String(e)
          }`,
        },
      };
    }
  }
  return { policy: null, info: none };
}

/** Roll one stored run up into its fleet row. Pure over the run + policy. */
function fleetRowFor(run: Run, summary: RunSummary, policy: Policy | null): FleetRun {
  const counts: FleetWarnings = { loop: 0, high_cost_step: 0, error: 0, total: 0 };
  for (const w of run.warnings) {
    if (WARNING_KINDS.includes(w.kind)) counts[w.kind] += 1;
    counts.total += 1;
  }
  const full = verifyRunFull(run);
  const policyResult = policy ? evaluatePolicy(run, policy) : null;
  return {
    id: run.id,
    name: run.name,
    startedAt: run.startedAt,
    endedAt: run.endedAt,
    ingestedAt: summary.ingestedAt,
    status: run.status,
    currency: run.currency,
    steps: run.totals.steps,
    tokens: run.totals.tokens,
    cost: run.totals.cost,
    durationMs: run.totals.durationMs,
    runHash: run.runHash,
    warnings: counts,
    warningMessages: run.warnings.map((w) => w.message),
    signed: run.signature !== undefined,
    keyId: run.signature?.keyId ?? null,
    chainOk: full.chain.ok,
    signatureOk: full.signature.ok,
    integrityMessage: !full.chain.ok
      ? full.chain.message
      : !full.signature.ok
        ? full.signature.message
        : full.chain.message,
    policyOk: policyResult ? policyResult.ok : null,
    policyViolations: policyResult
      ? policyResult.violations.map((v) => ({ rule: v.rule, message: v.message }))
      : [],
  };
}

/**
 * Memo for fleet rows, keyed by the run's own integrity anchor.
 *
 * Rolling a run up means parsing it and re-hashing every step, and the fleet
 * view polls. The store is append-only, so a row can only change if the run
 * itself changed — and the only in-place path (redaction) rewrites `runHash` by
 * construction. Keying on id + runHash + ingestedAt therefore makes a stale hit
 * impossible rather than merely unlikely.
 */
class FleetCache {
  private rows = new Map<string, FleetRun>();
  private static readonly MAX = 4096;

  get(key: string): FleetRun | undefined {
    return this.rows.get(key);
  }

  set(key: string, row: FleetRun): void {
    this.rows.set(key, row);
  }

  /** Drop everything not referenced by the current listing (prunes, redactions). */
  retain(liveKeys: Set<string>): void {
    if (this.rows.size <= FleetCache.MAX && this.rows.size === liveKeys.size) return;
    for (const key of this.rows.keys()) {
      if (!liveKeys.has(key)) this.rows.delete(key);
    }
  }
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
  /** Max request body in bytes (default DEFAULT_BODY_LIMIT). */
  bodyLimit?: number;
  /** Ingest requests per IP per minute; 0 disables (default DEFAULT_RATE_LIMIT). */
  rateLimit?: number;
  /**
   * Guardrail policy the fleet view scores every run against. Overrides the
   * TRACEGLASS_POLICY / ~/.traceglass/policy.json discovery.
   */
  policy?: Policy;
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

/** Human-readable byte size for limit messages. */
function mib(bytes: number): string {
  return `${(bytes / (1024 * 1024)).toFixed(bytes % (1024 * 1024) === 0 ? 0 : 1)} MiB`;
}

/**
 * Build the Fastify app: JSON API over the run store plus the static web SPA.
 * By default (dashboard mode) the store is read-only from the server's
 * perspective; serve mode adds authenticated collector ingest routes.
 */
export function buildServer(store: RunStore, opts: ServerOptions = {}): FastifyInstance {
  const bodyLimit = opts.bodyLimit ?? DEFAULT_BODY_LIMIT;
  const rateLimit = opts.rateLimit ?? DEFAULT_RATE_LIMIT;
  const app = Fastify({ logger: false, bodyLimit });

  /**
   * The 413 body, shared by the early content-length check and the parser
   * backstop. Fastify's stock 413 says only "Request body is too large", which
   * tells an operator nothing about what to change; name the limit and the flag.
   */
  const tooLarge = (reply: FastifyReply) =>
    reply.code(413).send({
      error: 'payload too large',
      message:
        `Request body exceeds the ${mib(bodyLimit)} limit. Split the trace, or raise ` +
        `the limit with --body-limit <MiB> (or TRACEGLASS_BODY_LIMIT).`,
      limitBytes: bodyLimit,
    });

  app.setErrorHandler((raw, _req, reply) => {
    const error = raw as { code?: string; statusCode?: number; message?: string };
    if (error.code === 'FST_ERR_CTP_BODY_TOO_LARGE' || error.statusCode === 413) {
      return tooLarge(reply);
    }
    const status = error.statusCode && error.statusCode >= 400 ? error.statusCode : 500;
    return reply.code(status).send({ error: error.message ?? 'internal server error' });
  });

  // Reject an over-limit body from its declared content-length, before a single
  // byte is buffered. Fastify's own bodyLimit only trips partway through the
  // upload, which both wastes the buffering and tends to reset the connection
  // mid-write — the client then sees a socket error instead of a clear 413.
  // A declared length can lie, or be absent under chunked encoding, so the
  // parser limit above stays as the backstop.
  app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > bodyLimit) return tooLarge(reply);
  });

  if (rateLimit > 0) {
    const limiter = new RateLimiter(rateLimit);
    // onRequest, so a flood is turned away BEFORE the body is read — the whole
    // point of the limit. It runs ahead of the auth gate on purpose: an
    // unauthenticated flood is exactly the traffic worth shedding early.
    app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
      if (req.method !== 'POST' || !INGEST_ROUTES.has(authPath(req))) return;
      const { allowed, remaining, resetAt } = limiter.take(req.ip);
      const retryAfter = Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
      reply.header('x-ratelimit-limit', String(rateLimit));
      reply.header('x-ratelimit-remaining', String(remaining));
      reply.header('x-ratelimit-reset', String(retryAfter));
      if (!allowed) {
        return reply
          .code(429)
          .header('retry-after', String(retryAfter))
          .send({
            error: 'too many requests',
            message: `Ingest is limited to ${rateLimit} requests per minute per client. Retry in ${retryAfter}s.`,
            limit: rateLimit,
            retryAfterSeconds: retryAfter,
          });
      }
    });
  }

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

  /*
   * Fleet rollup (v0.10): every stored run scored for triage in one response.
   * Read-only by construction — it opens no write path the other GETs don't.
   */
  const { policy: fleetPolicy, info: fleetPolicyInfo } = resolvePolicy(opts.policy);
  const fleetCache = new FleetCache();
  app.get('/api/fleet', async (): Promise<FleetResponse> => {
    const summaries = store.listRuns();
    const keys = new Set<string>();
    const runs: FleetRun[] = [];
    for (const summary of summaries) {
      const key = `${summary.id} ${summary.runHash} ${summary.ingestedAt}`;
      keys.add(key);
      const cached = fleetCache.get(key);
      if (cached) {
        runs.push(cached);
        continue;
      }
      const run = store.getRun(summary.id);
      // Raced with a prune between listing and loading — simply not in the fleet.
      if (!run) continue;
      const row = fleetRowFor(run, summary, fleetPolicy);
      fleetCache.set(key, row);
      runs.push(row);
    }
    fleetCache.retain(keys);
    return { runs, policy: fleetPolicyInfo, generatedAt: new Date().toISOString() };
  });

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
  /** Max request body in bytes (default DEFAULT_BODY_LIMIT). */
  bodyLimit?: number;
  /** Ingest requests per IP per minute; 0 disables (default DEFAULT_RATE_LIMIT). */
  rateLimit?: number;
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
    ...(opts.bodyLimit !== undefined ? { bodyLimit: opts.bodyLimit } : {}),
    ...(opts.rateLimit !== undefined ? { rateLimit: opts.rateLimit } : {}),
  });
  await app.listen({ port: opts.port, host: opts.host });
  return {
    fastify: app,
    port: opts.port,
    url: `http://${opts.host}:${opts.port}`,
    close: () => app.close(),
  };
}
