# Published as GHSA-69r3-wwg5-x52j

**Live advisory**, published 2026-07-26:
https://github.com/rahulbhardwaj94/traceglass/security/advisories/GHSA-69r3-wwg5-x52j

GitHub rated this **High**, matching the CVSS vector below. No CVE was
requested. This file is the source text the advisory was created from.

---

**Title:** `traceglass serve` returns every stored run without a token when the
request path is percent-encoded

**Package:** `traceglass` (npm)
**Affected versions:** `>=0.3.0 <0.7.2`
**Patched version:** `0.7.2`
**Severity (proposed):** High — CVSS 3.1 **7.5**
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
**Weaknesses:** CWE-863 (Incorrect Authorization), CWE-172 (Encoding Confusion)

## Summary

When `traceglass serve` is bound to a non-loopback interface, reads of the JSON
API are supposed to require a bearer token. The authorization gate decided
whether a request was an API request by testing the **raw** request target:

```js
req.url.startsWith('/api');
```

Fastify's router decodes percent-escapes *before* matching a route. A request
for `/%61pi/runs` therefore failed that prefix test — so the gate concluded it
was not an API request and skipped authorization — and was then routed to the
`/api/runs` handler anyway. The response was the complete run store.

## Impact

An unauthenticated attacker who can reach the port reads **every stored run**:
step labels, tool names, full input and output payloads, token counts, costs,
and any PII that has not been redacted. For a tool whose purpose is to hold
audit evidence, this is a disclosure of the entire evidence set.

Only deployments that actually require read auth are affected:

- `traceglass serve --host 0.0.0.0` (or any non-loopback bind)
- the published Docker image, whose entrypoint binds `0.0.0.0`

Loopback-only runs never set `requireAuthForReads`, so they were not affected —
their reads were open by design and by scope. The affected configuration is
precisely the one the token exists to protect, which is why this is rated High
despite being configuration-dependent.

`POST` endpoints were **not** affected. Ingest was gated on the HTTP method
rather than the path, so evidence could not be forged or injected through this
bug. The impact is confidentiality only; integrity and availability are
unaffected, and no signature or hash-chain guarantee is weakened.

## Proof of concept

Against a vulnerable version (0.3.0–0.7.1):

```sh
traceglass serve --host 0.0.0.0 --port 4318 --token s3cret &

# Correctly refused:
curl -s -o /dev/null -w '%{http_code}\n' http://HOST:4318/api/runs
# 401

# Bypass — same handler, no token:
curl -s -o /dev/null -w '%{http_code}\n' http://HOST:4318/%61pi/runs
# 200
```

The body returned by the second request is byte-identical to the authorized
response. Any percent-encoding of a character in `/api` works; `%61` for `a` is
just the shortest.

## Patches

Upgrade to **0.7.2**.

The fix authorizes against the route Fastify actually matched
(`req.routeOptions.url`), which is already canonical, and falls back to the
decoded pathname so an unrouted request cannot slip through undecoded either.
Matching the router's own normalization is the point: the gate and the router
now agree on what the path is.

A regression test ships with the fix and fails against the previous
`server.ts`.

0.7.2 also updates `@fastify/static` to 10.1.2, which clears a related
authorization bypass via non-canonical paths and a route-guard bypass via path
traversal in that dependency.

## Workarounds

If you cannot upgrade immediately:

- Bind to loopback only (`traceglass serve` with the default host) and reach it
  through an SSH tunnel or a reverse proxy that terminates auth itself.
- Put the collector behind a proxy that rejects or normalizes percent-encoded
  request paths before they reach traceglass, and enforce the bearer token at
  the proxy.
- Restrict access to the port at the network level.

Rotating the bearer token does **not** mitigate this — the bug skips the token
check entirely.

## Indicators

Access logs from an affected deployment will show `200` responses for paths that
are not literally `/api/...` but resolve to it — anything containing `%` in the
path segment that decodes into `api`. Because the requests were served
normally, there is no error signal to look for; absence of evidence here is not
evidence of absence.

If your deployment was reachable from an untrusted network while running an
affected version, treat the contents of the store as potentially disclosed.

## Credit

Found during internal review ahead of the 0.7.2 release.
