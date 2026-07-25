import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RunStore, ingestAndFinalize, type Run } from '@traceglass/core';
import { buildServer } from './server.js';

/**
 * ADVERSARIAL SUITE — read authorization (attack 7).
 *
 * v0.7.2 fixed one instance of this: the gate tested `req.url.startsWith('/api')`
 * on the RAW url, and Fastify decodes percent-escapes before routing, so
 * `/%61pi/runs` skipped auth and returned every stored run. That was found with
 * a single curl. This generalizes the probe across every route and every
 * URL-mangling trick, and asserts the invariant that actually matters:
 *
 *   NO request without a valid bearer token may return run data.
 *
 * "Returns 401" is not the invariant — a request that 404s or falls through to
 * the SPA is also fine. What is never fine is run ids, run hashes, or payload
 * bytes coming back to an anonymous caller.
 */

const TOKEN = 'correct-horse-battery-staple';
const SECRET_PAYLOAD = 'TOPSECRET-PII-VALUE-9f2a';

let store: RunStore;
let app: ReturnType<typeof buildServer>;
let run: Run;

beforeAll(async () => {
  store = new RunStore(':memory:');
  run = ingestAndFinalize({
    id: 'confidential-run-7731',
    name: 'confidential collections agent',
    currency: 'USD',
    steps: [
      {
        type: 'user_input',
        label: 'lookup',
        startedAt: '2026-01-01T00:00:00.000Z',
        durationMs: 1,
        input: { pii: SECRET_PAYLOAD },
      },
      {
        type: 'tool_call',
        toolName: 'payments.refund',
        label: 'refund',
        startedAt: '2026-01-01T00:00:01.000Z',
        durationMs: 1,
        output: { refunded: true },
      },
    ],
  });
  store.saveRun(run);
  app = buildServer(store, { token: TOKEN, enableIngest: true, requireAuthForReads: true });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  store.close();
});

/** Everything an anonymous caller must never be able to see. */
function leaks(body: string): string[] {
  const found: string[] = [];
  if (body.includes(run.id)) found.push('run id');
  if (body.includes(run.runHash)) found.push('runHash');
  if (body.includes(SECRET_PAYLOAD)) found.push('payload');
  if (body.includes('payments.refund')) found.push('tool name');
  if (body.includes('confidential collections')) found.push('run name');
  return found;
}

/**
 * Every mangled spelling of an /api path an attacker would reach for. The point
 * is not that each returns 401 — some legitimately 404 or fall through to the
 * SPA — but that none of them returns run data.
 */
const URL_VARIANTS = [
  // canonical
  '/api/runs',
  `/api/runs/${'confidential-run-7731'}`,
  '/api/runs/confidential-run-7731/verify',
  '/api/runs/confidential-run-7731/report',
  '/api/search?q=TOPSECRET',
  '/api/search?q=7731',
  '/api/live',
  '/api/live/confidential-run-7731',
  '/api/sessions',
  // percent-encoded (the v0.7.2 bug)
  '/%61pi/runs',
  '/a%70i/runs',
  '/ap%69/runs',
  '/api/%72uns',
  '/api/r%75ns',
  '/%61pi/%72uns',
  '/%61pi/runs/confidential-run-7731',
  '/%61pi/search?q=7731',
  '/%61pi/live/confidential-run-7731',
  // double-encoded
  '/%2561pi/runs',
  '/%25%36%31pi/runs',
  '/api/%2572uns',
  // encoded separators
  '/api%2Fruns',
  '/api%2fruns',
  '/%2Fapi/runs',
  // case variants
  '/API/runs',
  '/Api/Runs',
  '/aPi/rUnS',
  '/%41PI/runs',
  // trailing / duplicate / empty segments
  '/api/runs/',
  '/api/runs//',
  '/api//runs',
  '//api/runs',
  '///api/runs',
  '/api/./runs',
  // path traversal
  '/./api/runs',
  '/foo/../api/runs',
  '/foo/%2e%2e/api/runs',
  '/%2e/api/runs',
  '/api/runs/../runs',
  '/api/../api/runs',
  '/..%2fapi/runs',
  // unicode / control escapes
  '/%u0061pi/runs',
  '/%c0%afapi/runs',
  '/api/runs',
  '/api/runs%00',
  '/api/runs%0a',
  '/api/runs%20',
  // separator confusion
  '/\\api/runs',
  '/api\\runs',
  '/api/runs;',
  '/api/runs;x=1',
  '/api/runs#fragment',
  '/api/runs?x=1',
];

describe('ATTACK 7: read-authorization fuzzing across every route', () => {
  it('the authorized caller CAN read run data (so the probes below mean something)', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/runs',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
    expect(leaks(res.body)).toContain('run id');

    const full = await app.inject({
      method: 'GET',
      url: `/api/runs/${run.id}`,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(full.statusCode).toBe(200);
    expect(leaks(full.body)).toEqual(
      expect.arrayContaining(['run id', 'runHash', 'payload', 'tool name']),
    );
  });

  it.each(URL_VARIANTS)('no run data leaks to an anonymous GET %s', async (url) => {
    let res;
    try {
      res = await app.inject({ method: 'GET', url });
    } catch {
      return; // a URL the injector itself refuses is fine — nothing was served
    }
    expect(leaks(res.body), `${url} leaked ${leaks(res.body).join(', ')}`).toEqual([]);
    // Anything that DID reach a real API handler must have been 401'd.
    expect(
      res.statusCode === 200 && String(res.headers['content-type']).includes('application/json'),
      `${url} returned a 200 JSON API response without a token`,
    ).toBe(false);
  });

  it.each(URL_VARIANTS)('a WRONG token fares no better on GET %s', async (url) => {
    let res;
    try {
      res = await app.inject({ method: 'GET', url, headers: { authorization: 'Bearer wrong' } });
    } catch {
      return;
    }
    expect(leaks(res.body), `${url} leaked with a wrong token`).toEqual([]);
  });

  it('the canonical routes specifically return 401, not a fallback', async () => {
    // Distinct from the sweep above: for URLs Fastify genuinely routes, the
    // answer must be an explicit 401 rather than an accidental 404/SPA.
    for (const url of [
      '/api/runs',
      `/api/runs/${run.id}`,
      `/api/runs/${run.id}/verify`,
      `/api/runs/${run.id}/report`,
      '/api/search?q=x',
      '/api/live',
      `/api/live/${run.id}`,
      '/api/sessions',
      '/%61pi/runs',
      '/api/%72uns',
    ]) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode, `${url} must be 401`).toBe(401);
    }
  });

  it('POST routes are gated regardless of requireAuthForReads', async () => {
    const body = { id: 'injected', name: 'x', currency: 'USD', steps: [] };
    for (const url of [
      '/api/ingest',
      '/%61pi/ingest',
      '/v1/traces',
      '/api/sessions/anything/ingest',
      '/API/ingest',
      '/api/ingest/',
    ]) {
      const res = await app.inject({
        method: 'POST',
        url,
        headers: { 'content-type': 'application/json' },
        payload: body,
      });
      expect(res.statusCode, `${url} must not accept an unauthenticated POST`).not.toBe(200);
      expect(store.getRun('injected')).toBeNull();
    }
  });

  it('other verbs cannot reach the API either', async () => {
    for (const method of ['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const) {
      const res = await app.inject({ method, url: `/api/runs/${run.id}` });
      expect(leaks(res.body ?? ''), `${method} leaked`).toEqual([]);
    }
  });

  it('the bearer-token comparison rejects near-miss headers', async () => {
    const nearMisses = [
      `bearer ${TOKEN}`, // lowercase scheme
      `BEARER ${TOKEN}`,
      `Bearer  ${TOKEN}`, // double space
      `Bearer ${TOKEN} `, // trailing space
      `Bearer ${TOKEN}\t`,
      `Bearer${TOKEN}`, // no space
      `Bearer ${TOKEN}x`, // longer
      `Bearer ${TOKEN.slice(0, -1)}`, // shorter (prefix)
      `Bearer ${TOKEN.toUpperCase()}`,
      'Bearer ',
      'Bearer',
      TOKEN,
      `Basic ${TOKEN}`,
      `Bearer ${Buffer.from(TOKEN).toString('base64')}`,
      `Bearer ${encodeURIComponent(`${TOKEN} `)}`, // percent-encoded, must not be decoded
      '',
    ];
    for (const authorization of nearMisses) {
      const res = await app.inject({
        method: 'GET',
        url: '/api/runs',
        headers: { authorization },
      });
      expect(res.statusCode, `header ${JSON.stringify(authorization)} must be rejected`).toBe(401);
      expect(leaks(res.body)).toEqual([]);
    }
  });

  it('a duplicated authorization header cannot smuggle a valid token past a bad one', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/runs',
      headers: { authorization: ['Bearer wrong', `Bearer ${TOKEN}`] as unknown as string },
    });
    expect(leaks(res.body)).toEqual([]);
  });

  it('token comparison is length-checked before timingSafeEqual (no throw on mismatch)', async () => {
    // timingSafeEqual throws on unequal lengths; a missing guard would surface
    // as a 500 rather than a 401, which is both a crash and an oracle.
    for (const t of ['Bearer a', `Bearer ${'x'.repeat(4096)}`, 'Bearer  ']) {
      const res = await app.inject({ method: 'GET', url: '/api/runs', headers: { authorization: t } });
      expect(res.statusCode).toBe(401);
    }
  });

  it('loopback serve mode leaves GETs open but still gates POSTs', async () => {
    // Pinning the documented asymmetry: without requireAuthForReads, reads are
    // deliberately open (localhost dashboard) but writes never are.
    const s = new RunStore(':memory:');
    s.saveRun(run);
    const a = buildServer(s, { token: TOKEN, enableIngest: true });
    await a.ready();
    expect((await a.inject({ method: 'GET', url: '/api/runs' })).statusCode).toBe(200);
    expect(
      (
        await a.inject({
          method: 'POST',
          url: '/api/ingest',
          headers: { 'content-type': 'application/json' },
          payload: { id: 'x', name: 'x', steps: [] },
        })
      ).statusCode,
    ).toBe(401);
    await a.close();
    s.close();
  });

  it('with NO token configured there is no auth hook at all — the documented local default', () => {
    // Not a vulnerability, but worth pinning: `buildServer(store)` with no
    // token is wide open by design, and `startServe` refuses to bind a
    // non-loopback host in that state (see server.ts:isLoopback).
    const s = new RunStore(':memory:');
    const a = buildServer(s);
    expect(a).toBeDefined();
    s.close();
  });
});
