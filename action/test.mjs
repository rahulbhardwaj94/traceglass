/**
 * End-to-end exercise of the action WITHOUT publishing it or pushing anything.
 *
 *   npm run build && node action/test.mjs
 *
 * It records a real run with the SDK, exports a real `.tgev`, then runs
 * `main.mjs` exactly the way the composite step does — same `INPUT_*`
 * environment, same `GITHUB_OUTPUT` / `GITHUB_STEP_SUMMARY` / `GITHUB_EVENT_PATH`
 * contract — and asserts on exit codes, outputs and the rendered Markdown.
 *
 * The pull-request comment is exercised against a local stub of the REST API
 * (`github-api-url` is a real action input, for GitHub Enterprise Server), so
 * the create-then-update path is covered without a network or a token.
 */
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderMarkdown, markerFor } from './report.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const CLI = join(REPO, 'packages', 'cli', 'dist', 'bin.js');
const MAIN = join(HERE, 'main.mjs');

if (!existsSync(CLI)) {
  console.error(`No built CLI at ${CLI}. Run \`npm run build\` first.`);
  process.exit(1);
}

const WORK = mkdtempSync(join(tmpdir(), 'traceglass-action-test-'));
const HOME = join(WORK, 'home');
mkdirSync(HOME, { recursive: true });

let passed = 0;
const failures = [];
const check = (name, actual, expected) => {
  if (Object.is(actual, expected)) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failures.push(`${name}\n       expected ${JSON.stringify(expected)}\n       actual   ${JSON.stringify(actual)}`);
    console.log(`  FAIL ${name}`);
  }
};
const checkThat = (name, condition) => check(name, Boolean(condition), true);

function run(command, args, env = {}) {
  return new Promise((res) => {
    const child = spawn(command, args, {
      cwd: REPO,
      env: { ...process.env, TRACEGLASS_HOME: HOME, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => res({ code, stdout, stderr }));
  });
}

const node = (args, env) => run(process.execPath, args, env);

/** Parse the `key=value` / heredoc format the runner uses for $GITHUB_OUTPUT. */
function parseOutputs(file) {
  const out = {};
  const lines = readFileSync(file, 'utf8').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const heredoc = line.match(/^([^=<]+)<<(.+)$/);
    if (heredoc) {
      const [, key, delim] = heredoc;
      const body = [];
      while (++i < lines.length && lines[i] !== delim) body.push(lines[i]);
      out[key] = body.join('\n');
      continue;
    }
    const eq = line.indexOf('=');
    if (eq > 0) out[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return out;
}

/* ================================================================== *
 * fixtures: a real run, a real .tgev                                  *
 * ================================================================== */

console.log('\n# fixtures');
await node([CLI, 'keygen']);
const agent = await node([join(REPO, 'docs', 'examples', 'collections-agent.mjs'), 'action-test']);
check('agent recorded', agent.code, 0);

const TGEV = join(WORK, 'action-test.tgev');
const exported = await node([CLI, 'export', 'action-test', '-o', TGEV]);
check('exported evidence', exported.code, 0);
checkThat('.tgev exists', existsSync(TGEV));

const STRICT_POLICY = join(WORK, 'strict.json');
writeFileSync(
  STRICT_POLICY,
  JSON.stringify(
    {
      name: 'collections guardrails',
      rules: {
        maxCostPerRun: 10,
        requireApprovalFor: ['payments.*'],
        requireSignature: true,
        forbidWarnings: ['loop'],
      },
    },
    null,
    2,
  ),
);

const LENIENT_POLICY = join(WORK, 'lenient.json');
writeFileSync(
  LENIENT_POLICY,
  JSON.stringify({ name: 'smoke', rules: { maxCostPerRun: 1000, requireSignature: true } }, null, 2),
);

/* ================================================================== *
 * the runner contract                                                 *
 * ================================================================== */

let seq = 0;
function actionEnv(extra = {}) {
  const dir = join(WORK, `step-${seq++}`);
  mkdirSync(dir, { recursive: true });
  const outputs = join(dir, 'outputs.txt');
  const summary = join(dir, 'summary.md');
  writeFileSync(outputs, '');
  writeFileSync(summary, '');
  return {
    dir,
    outputs,
    summary,
    env: {
      GITHUB_OUTPUT: outputs,
      GITHUB_STEP_SUMMARY: summary,
      GITHUB_SERVER_URL: 'https://github.com',
      GITHUB_REPOSITORY: 'acme/agents',
      GITHUB_RUN_ID: '42',
      INPUT_BIN: CLI,
      INPUT_POLICY: STRICT_POLICY,
      INPUT_EVIDENCE: TGEV,
      INPUT_COMMENT: 'false',
      INPUT_SUMMARY: 'true',
      INPUT_FAIL_ON_VIOLATION: 'true',
      ...extra,
    },
  };
}

/* ------------------------------------------------------------------ */
console.log('\n# a violating record fails the build');
{
  const ctx = actionEnv();
  const r = await node([MAIN], ctx.env);
  check('exit code', r.code, 1);
  const outputs = parseOutputs(ctx.outputs);
  check('ok output', outputs.ok, 'false');
  check('violations output', outputs.violations, '3');
  check('run-id output', outputs['run-id'], 'action-test');
  checkThat('emitted an ::error:: annotation', r.stdout.includes('::error::traceglass:'));

  const summary = readFileSync(ctx.summary, 'utf8');
  checkThat('summary names the failure', summary.includes('record FAILED'));
  checkThat('summary lists maxCostPerRun', summary.includes('maxCostPerRun'));
  checkThat('summary lists requireApprovalFor', summary.includes('requireApprovalFor'));
  checkThat('summary lists the loop warning', summary.includes('forbidWarnings'));
  checkThat('summary qualifies the signature', summary.includes('self-attested'));
  checkThat('report artefact written', existsSync(outputs.report));
  const raw = JSON.parse(readFileSync(outputs.json, 'utf8'));
  check('raw json carries the verdict', raw.check.ok, false);
}

/* ------------------------------------------------------------------ */
console.log('\n# a clean record passes');
{
  const ctx = actionEnv({ INPUT_POLICY: LENIENT_POLICY });
  const r = await node([MAIN], ctx.env);
  check('exit code', r.code, 0);
  const outputs = parseOutputs(ctx.outputs);
  check('ok output', outputs.ok, 'true');
  check('violations output', outputs.violations, '0');
  checkThat('summary says passed', readFileSync(ctx.summary, 'utf8').includes('record passed'));
}

/* ------------------------------------------------------------------ */
console.log('\n# fail-on-violation: false reports without failing');
{
  const ctx = actionEnv({ INPUT_FAIL_ON_VIOLATION: 'false' });
  const r = await node([MAIN], ctx.env);
  check('exit code', r.code, 0);
  check('ok output still false', parseOutputs(ctx.outputs).ok, 'false');
  checkThat('warned instead', r.stdout.includes('::warning::traceglass:'));
}

/* ------------------------------------------------------------------ */
console.log('\n# a tampered record is caught');
{
  const tampered = join(WORK, 'tampered.tgev');
  const original = readFileSync(TGEV, 'utf8');
  checkThat('tamper target present', original.includes('"amount": 18400'));
  writeFileSync(tampered, original.replace('"amount": 18400', '"amount": 184'));
  const ctx = actionEnv({ INPUT_EVIDENCE: tampered, INPUT_POLICY: LENIENT_POLICY });
  const r = await node([MAIN], ctx.env);
  check('exit code', r.code, 1);
  const summary = readFileSync(ctx.summary, 'utf8');
  checkThat('summary names the altered leaf', summary.includes('input.amount'));
  checkThat('integrity reported as failed', summary.includes('Integrity check FAILED'));
}

/* ------------------------------------------------------------------ */
console.log('\n# anchors: a local anchor is reported, and --require-external gates on it');
{
  const anchors = join(WORK, 'anchors.jsonl');
  const anchored = await node([CLI, 'anchor', 'action-test', '-o', anchors]);
  check('anchor written', anchored.code, 0);

  const ctx = actionEnv({ INPUT_POLICY: LENIENT_POLICY, INPUT_ANCHORS: anchors });
  const r = await node([MAIN], ctx.env);
  check('exit code with a local anchor', r.code, 0);
  check('anchor-strength output', parseOutputs(ctx.outputs)['anchor-strength'], 'local');
  checkThat('summary says local only', readFileSync(ctx.summary, 'utf8').includes('Anchor: local only'));

  const strict = actionEnv({
    INPUT_POLICY: LENIENT_POLICY,
    INPUT_ANCHORS: anchors,
    INPUT_REQUIRE_EXTERNAL: 'true',
  });
  const r2 = await node([MAIN], strict.env);
  check('require-external fails on a local anchor', r2.code, 1);
  check('ok output', parseOutputs(strict.outputs).ok, 'false');
}

/* ------------------------------------------------------------------ */
console.log('\n# bad input is refused, not papered over');
{
  const ctx = actionEnv({ INPUT_POLICY: join(WORK, 'does-not-exist.json') });
  const r = await node([MAIN], ctx.env);
  check('exit code', r.code, 1);
  checkThat('names the missing policy', r.stdout.includes('Policy file not found'));
}
{
  const ctx = actionEnv({ INPUT_REQUIRE_EXTERNAL: 'true' });
  const r = await node([MAIN], ctx.env);
  check('require-external without anchors is refused', r.code, 1);
  checkThat('explains why', r.stdout.includes('needs `anchors`'));
}

/* ================================================================== *
 * the pull-request comment, against a stub API                        *
 * ================================================================== */

console.log('\n# pull-request comment: created once, updated thereafter');
{
  /** Minimal stand-in for the three REST calls the action makes. */
  const comments = [];
  const calls = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      calls.push(`${req.method} ${req.url.split('?')[0]}`);
      const send = (code, payload) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      if (req.method === 'GET' && req.url.startsWith('/repos/acme/agents/issues/7/comments')) {
        const page = Number(new URL(req.url, 'http://x').searchParams.get('page') ?? '1');
        return send(200, page === 1 ? comments : []);
      }
      if (req.method === 'POST' && req.url.startsWith('/repos/acme/agents/issues/7/comments')) {
        const created = { id: 1001, body: JSON.parse(body).body };
        comments.push(created);
        return send(201, created);
      }
      const patch = req.url.match(/^\/repos\/acme\/agents\/issues\/comments\/(\d+)$/);
      if (req.method === 'PATCH' && patch) {
        const target = comments.find((c) => String(c.id) === patch[1]);
        target.body = JSON.parse(body).body;
        return send(200, target);
      }
      send(404, { message: 'not found' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const apiUrl = `http://127.0.0.1:${server.address().port}`;

  const eventPath = join(WORK, 'event.json');
  writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 7 } }));

  const commentEnv = {
    INPUT_COMMENT: 'true',
    INPUT_GITHUB_TOKEN: 'stub-token',
    INPUT_GITHUB_API_URL: apiUrl,
    GITHUB_EVENT_PATH: eventPath,
  };

  const first = await node([MAIN], actionEnv(commentEnv).env);
  check('first run exits 1 (record violates)', first.code, 1);
  check('one comment now exists', comments.length, 1);
  checkThat('comment carries the update marker', comments[0].body.startsWith(markerFor(`${TGEV}|${STRICT_POLICY}`)));
  checkThat('comment names the run', comments[0].body.includes('action-test'));
  checkThat('posted', first.stdout.includes('Posted pull-request comment'));

  const second = await node([MAIN], actionEnv(commentEnv).env);
  check('second run still exits 1', second.code, 1);
  check('still exactly one comment', comments.length, 1);
  checkThat('updated in place', second.stdout.includes('Updated pull-request comment'));
  checkThat('a PATCH was issued', calls.some((c) => c.startsWith('PATCH ')));

  // A different policy must get its own comment, not clobber the first.
  const other = await node(
    [MAIN],
    actionEnv({ ...commentEnv, INPUT_POLICY: LENIENT_POLICY }).env,
  );
  check('a second policy gets its own comment', comments.length, 2);
  check('and passes', other.code, 0);

  // No PR in the event: skip, do not crash.
  writeFileSync(eventPath, JSON.stringify({ push: true }));
  const noPr = await node([MAIN], actionEnv({ ...commentEnv, INPUT_POLICY: LENIENT_POLICY }).env);
  check('no pull request: still exits cleanly', noPr.code, 0);
  checkThat('and says so', noPr.stdout.includes('No pull request in this event'));

  // An API that refuses must warn, never flip a failing verdict to passing.
  writeFileSync(eventPath, JSON.stringify({ pull_request: { number: 999 } }));
  const denied = await node([MAIN], actionEnv(commentEnv).env);
  check('comment failure does not mask the verdict', denied.code, 1);
  checkThat('warned about the comment', denied.stdout.includes('Could not post the pull-request comment'));

  await new Promise((r) => server.close(r));
}

/* ================================================================== *
 * renderer unit checks                                                *
 * ================================================================== */

console.log('\n# renderer');
{
  const md = renderMarkdown({
    check: {
      runId: 'r1',
      ok: false,
      integrity: {
        ok: true,
        chain: { ok: true, message: 'Integrity check passed: chain intact.', storedRunHash: 'abc', hashVersion: 2 },
        signature: { ok: true, keyId: 'k', message: 'Signature OK (keyId k).' },
        redaction: { ok: true, attested: false, paths: ['a'], message: '1 redaction(s) recorded, UNATTESTED.' },
      },
      policy: {
        ok: false,
        policyName: 'p',
        violations: [{ rule: 'r', message: 'a | pipe and\na newline', stepIds: ['s1', 's2', 's3', 's4', 's5'] }],
      },
    },
    anchor: { matched: true, strength: 'external', provenExistedBy: '2026-07-26T00:00:00Z' },
    evidence: 'run.tgev',
    policyPath: 'p.json',
  });
  checkThat('escapes a pipe inside a table cell', md.includes('a \\| pipe and a newline'));
  checkThat('no raw newline leaks into the row', !md.includes('| r | a \\| pipe and\n'));
  checkThat('reports an external anchor as third-party evidence', md.includes('third-party evidence'));
  checkThat('truncates long step lists', md.includes('+1 more'));
  checkThat('flags an unattested redaction log', md.includes('UNATTESTED'));

  const clean = renderMarkdown({
    check: { runId: 'r2', ok: true, integrity: { ok: true, chain: { ok: true, message: 'ok' }, signature: { ok: true, keyId: 'k', message: 'Signature OK.' } }, policy: { ok: true, policyName: null, violations: [] } },
    evidence: 'x',
    policyPath: 'y',
  });
  checkThat('clean record renders a pass', clean.includes('record passed'));
  checkThat('and still carries the qualification', clean.includes('self-attested'));
}

/* ================================================================== */

rmSync(WORK, { recursive: true, force: true });
console.log(`\n${passed} checks passed, ${failures.length} failed`);
if (failures.length) {
  for (const f of failures) console.error('  FAIL ' + f);
  process.exit(1);
}
