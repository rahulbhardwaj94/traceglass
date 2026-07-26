import { createServer, type Server } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { ingestAndFinalize, type Run } from '@traceglass/core';
import {
  FileAnchorSink,
  Rfc3161AnchorSink,
  SigstoreAnchorSink,
  anchorRecordForRun,
  readAnchorFile,
  type AnchorRecord,
} from './anchors.js';
import { generateKeys, maybeSign } from './keys.js';

/**
 * Sink behaviour: the two product guarantees that are easy to break and
 * expensive to break — zero egress by default, and never losing evidence when
 * an external service misbehaves.
 *
 * Every test here runs against a LOCAL mock server on 127.0.0.1 or against a
 * stubbed fetch. Nothing reaches the internet, so this suite is meaningful in
 * CI with no network at all. There is no skip-if-offline path: a test that
 * quietly skips is worse than no test.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'test-fixtures');

let home: string;
let savedHome: string | undefined;
let run: Run;

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'tg-sink-'));
  savedHome = process.env.TRACEGLASS_HOME;
  process.env.TRACEGLASS_HOME = home;
  generateKeys();
  run = maybeSign(
    ingestAndFinalize({
      id: 'sink-run',
      name: 'sink test',
      currency: 'USD',
      steps: [
        { type: 'user_input', label: 'go', startedAt: '2026-01-01T00:00:00.000Z', durationMs: 1 },
      ],
    }),
  );
});

afterAll(() => {
  if (savedHome === undefined) delete process.env.TRACEGLASS_HOME;
  else process.env.TRACEGLASS_HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
});

interface MockRequest {
  body: Buffer;
  path: string;
  method: string;
  contentType: string;
}

/** Spin up a throwaway HTTP server and return its base URL. */
async function serve(
  handler: (req: MockRequest) => { status: number; type: string; body: Buffer | string },
): Promise<{ url: string; close: () => Promise<void>; hits: () => number }> {
  let hits = 0;
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      hits++;
      const out = handler({
        body: Buffer.concat(chunks),
        path: req.url ?? '',
        method: req.method ?? '',
        contentType: req.headers['content-type'] ?? '',
      });
      res.writeHead(out.status, { 'content-type': out.type });
      res.end(out.body);
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((r) => server.close(() => r())),
    hits: () => hits,
  };
}

const anchorsIn = (name: string) => join(home, name);

describe('zero network egress by default', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it('the default file sink never calls fetch, even once', async () => {
    /*
     * traceglass is local-first and says so in writing. This test fails loudly
     * the moment anything in the default anchoring path grows an outbound
     * request — including a "helpful" fallback.
     */
    let called = 0;
    globalThis.fetch = (async () => {
      called++;
      throw new Error('NETWORK ACCESS ATTEMPTED BY THE DEFAULT SINK');
    }) as typeof fetch;

    const path = anchorsIn('no-egress.jsonl');
    const sink = new FileAnchorSink(path);
    const outcomes = await sink.append([anchorRecordForRun(run)]);

    expect(called).toBe(0);
    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]!.error).toBeNull();
    expect(outcomes[0]!.proof).toBeNull();
    expect(readAnchorFile(path).records).toHaveLength(1);
  });

  it('reading and verifying anchors never calls fetch either', async () => {
    let called = 0;
    globalThis.fetch = (async () => {
      called++;
      throw new Error('NETWORK ACCESS ATTEMPTED DURING VERIFICATION');
    }) as typeof fetch;

    const path = anchorsIn('no-egress-verify.jsonl');
    await new FileAnchorSink(path).append([anchorRecordForRun(run)]);
    const file = readAnchorFile(path);
    expect(file.ok).toBe(true);
    expect(called).toBe(0);
  });
});

describe('RFC 3161 sink: failure is safe and obvious', () => {
  /**
   * The rule: if anchoring fails, the record is STILL captured and stored, the
   * failure is reported clearly, and nothing is ever marked anchored when it is
   * not. Losing an audit record because a timestamp service was down would be
   * a far worse bug than the missing timestamp.
   */

  async function expectSafeFailure(path: string, tsaUrl: string, matcher: RegExp): Promise<void> {
    const sink = new Rfc3161AnchorSink(new FileAnchorSink(path), { tsaUrl, timeoutMs: 2000 });
    const outcomes = await sink.append([anchorRecordForRun(run)]);

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]!.error).toMatch(matcher);
    expect(outcomes[0]!.proof).toBeNull();

    // The evidence survived...
    const file = readAnchorFile(path);
    expect(file.ok).toBe(true);
    expect(file.records).toHaveLength(1);
    expect(file.records[0]!.runId).toBe('sink-run');
    expect(file.records[0]!.runHash).toBe(run.runHash);
    // ...and is NOT dressed up as timestamped.
    expect(file.records[0]!.proof).toBeUndefined();
  }

  it('records the run locally when the TSA returns HTTP 500', async () => {
    const server = await serve(() => ({ status: 500, type: 'text/plain', body: 'boom' }));
    try {
      await expectSafeFailure(anchorsIn('tsa-500.jsonl'), server.url, /HTTP 500/);
      expect(server.hits()).toBe(1);
    } finally {
      await server.close();
    }
  });

  it('records the run locally when the TSA REJECTS the request', async () => {
    const rejected = readFileSync(join(FIXTURES, 'response-rejected.tsr'));
    const server = await serve(() => ({
      status: 200,
      type: 'application/timestamp-reply',
      body: rejected,
    }));
    try {
      await expectSafeFailure(anchorsIn('tsa-reject.jsonl'), server.url, /refused|rejection/i);
    } finally {
      await server.close();
    }
  });

  it('records the run locally when the TSA is unreachable', async () => {
    // Port 1 on loopback: connection refused, immediately and reliably.
    await expectSafeFailure(anchorsIn('tsa-down.jsonl'), 'http://127.0.0.1:1', /failed/i);
  });

  it('DISCARDS a token that does not verify rather than storing it', async () => {
    /*
     * The key discipline: a stored token nobody validated is theatre. Here the
     * TSA answers with a genuine, cryptographically valid token — but one
     * issued over a different document and with a nonce that does not answer
     * our request. It must be thrown away, not filed as proof.
     */
    const foreign = readFileSync(join(FIXTURES, 'response.tsr'));
    const server = await serve(() => ({
      status: 200,
      type: 'application/timestamp-reply',
      body: foreign,
    }));
    try {
      await expectSafeFailure(
        anchorsIn('tsa-wrong-token.jsonl'),
        server.url,
        /did not verify.*(messageImprint|nonce)/s,
      );
    } finally {
      await server.close();
    }
  });

  it('sends only the request DER — no run content crosses the wire', async () => {
    let seen = Buffer.alloc(0);
    const server = await serve((req) => {
      seen = req.body;
      return { status: 500, type: 'text/plain', body: 'no' };
    });
    try {
      const sink = new Rfc3161AnchorSink(new FileAnchorSink(anchorsIn('tsa-body.jsonl')), {
        tsaUrl: server.url,
        timeoutMs: 2000,
      });
      await sink.append([anchorRecordForRun(run)]);
    } finally {
      await server.close();
    }
    // A TimeStampReq is tiny and opaque: version, algorithm OID, digest, nonce.
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.length).toBeLessThan(200);
    const asText = seen.toString('latin1');
    expect(asText).not.toContain('sink-run');
    expect(asText).not.toContain(run.runHash);
    expect(asText).not.toContain('sink test');
  });
});

describe('Rekor sink: failure is safe and obvious', () => {
  it('records the run locally when Rekor rejects the submission', async () => {
    const server = await serve(() => ({
      status: 409,
      type: 'application/json',
      body: '{"code":409,"message":"entry already exists"}',
    }));
    const path = anchorsIn('rekor-409.jsonl');
    try {
      const sink = new SigstoreAnchorSink(new FileAnchorSink(path), {
        rekorUrl: server.url,
        timeoutMs: 2000,
      });
      const outcomes = await sink.append([anchorRecordForRun(run)]);
      expect(outcomes[0]!.error).toMatch(/HTTP 409/);
      expect(outcomes[0]!.proof).toBeNull();
    } finally {
      await server.close();
    }
    const file = readAnchorFile(path);
    expect(file.records).toHaveLength(1);
    expect(file.records[0]!.proof).toBeUndefined();
  });

  it('posts to the documented Rekor path and sends no run content', async () => {
    let seen: MockRequest | null = null;
    const server = await serve((req) => {
      seen = req;
      return { status: 500, type: 'application/json', body: '{}' };
    });
    try {
      const sink = new SigstoreAnchorSink(new FileAnchorSink(anchorsIn('rekor-body.jsonl')), {
        // A trailing slash must not produce a double slash in the path.
        rekorUrl: `${server.url}/`,
        timeoutMs: 2000,
      });
      await sink.append([anchorRecordForRun(run)]);
    } finally {
      await server.close();
    }
    const request = seen as MockRequest | null;
    expect(request).not.toBeNull();
    expect(request!.method).toBe('POST');
    expect(request!.path).toBe('/api/v1/log/entries');
    expect(request!.contentType).toContain('application/json');
    const seenBody = request!.body.toString('utf8');
    const proposal = JSON.parse(seenBody) as {
      kind: string;
      spec: { data: { hash: { value: string } } };
    };
    expect(proposal.kind).toBe('hashedrekord');
    expect(proposal.spec.data.hash.value).toMatch(/^[0-9a-f]{64}$/);
    expect(seenBody).not.toContain('sink-run');
    expect(seenBody).not.toContain(run.runHash);
  });

  it('refuses to submit at all when there is no local signing key', async () => {
    const noKeyHome = mkdtempSync(join(tmpdir(), 'tg-sink-nokey-'));
    const saved = process.env.TRACEGLASS_HOME;
    process.env.TRACEGLASS_HOME = noKeyHome;
    let hits = 0;
    const server = await serve(() => {
      hits++;
      return { status: 201, type: 'application/json', body: '{}' };
    });
    try {
      const path = join(noKeyHome, 'rekor-nokey.jsonl');
      const sink = new SigstoreAnchorSink(new FileAnchorSink(path), {
        rekorUrl: server.url,
        timeoutMs: 2000,
      });
      const outcomes = await sink.append([anchorRecordForRun(run)]);
      expect(outcomes[0]!.error).toMatch(/needs a local signing key/);
      expect(hits).toBe(0); // nothing was sent
      expect(readAnchorFile(path).records).toHaveLength(1); // still recorded
    } finally {
      await server.close();
      process.env.TRACEGLASS_HOME = saved;
      rmSync(noKeyHome, { recursive: true, force: true });
    }
  });
});

describe('chaining across multiple appends', () => {
  it('keeps the chain intact when records are appended in separate batches', async () => {
    const path = anchorsIn('multi-batch.jsonl');
    const sink = new FileAnchorSink(path);
    for (const id of ['a', 'b', 'c']) {
      await sink.append([
        {
          version: 2,
          runId: `run-${id}`,
          runHash: id.repeat(64),
          anchoredAt: new Date().toISOString(),
        } satisfies AnchorRecord,
      ]);
    }
    const file = readAnchorFile(path);
    expect(file.records).toHaveLength(3);
    expect(file.ok).toBe(true);
    expect(file.records[0]!.prev).toBeNull();
    expect(file.records[1]!.prev).toMatch(/^[0-9a-f]{64}$/);
    expect(file.records[2]!.prev).not.toBe(file.records[1]!.prev);
  });

  it('tolerates a legacy v1 file with no chain, without claiming it is intact', async () => {
    // Records written by 0.8 have no `prev`. They must still be readable, and
    // must not be reported as chain failures — but they earn no chain guarantee.
    const path = anchorsIn('legacy.jsonl');
    const legacy: AnchorRecord = {
      version: 1,
      runId: 'legacy-run',
      runHash: 'd'.repeat(64),
      anchoredAt: '2026-01-01T00:00:00.000Z',
    };
    const { writeFileSync } = await import('node:fs');
    writeFileSync(path, JSON.stringify(legacy) + '\n');
    const file = readAnchorFile(path);
    expect(file.ok).toBe(true);
    expect(file.records).toHaveLength(1);
    expect(file.records[0]!.version).toBe(1);

    // Appending a v2 record chains onto it from that point forward.
    await new FileAnchorSink(path).append([
      { version: 2, runId: 'new-run', runHash: 'e'.repeat(64), anchoredAt: 'now' },
    ]);
    const after = readAnchorFile(path);
    expect(after.ok).toBe(true);
    expect(after.records[1]!.prev).toMatch(/^[0-9a-f]{64}$/);
  });
});
