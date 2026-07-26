/**
 * Entry point for the traceglass GitHub Action (see action.yml).
 *
 *   1. run `traceglass check <evidence> --policy <policy> --json`
 *   2. optionally run `traceglass verify --anchors ...` for the anchor verdict
 *   3. render the compliance summary
 *   4. write it to the job summary, and to a PR comment it updates in place
 *   5. exit 1 if the record failed and `fail-on-violation` is on
 *
 * Zero dependencies: Node 20's built-in `fetch` does the REST calls, so the
 * action needs no `node_modules`, no bundling step and no committed `dist/`.
 * That is deliberate for a product whose pitch is that you can audit its
 * supply chain.
 */
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { renderMarkdown, markerFor } from './report.mjs';

/* ------------------------------------------------------------------ */
/* inputs                                                              */
/* ------------------------------------------------------------------ */

const input = (name) => (process.env[`INPUT_${name}`] ?? '').trim();
const flag = (name, dflt = false) => {
  const v = input(name).toLowerCase();
  if (v === '') return dflt;
  return v === 'true' || v === '1' || v === 'yes';
};

const EVIDENCE = input('EVIDENCE');
const POLICY = input('POLICY');
const ANCHORS = input('ANCHORS');
const TSA_CERT = input('TSA_CERT');
const REKOR_KEY = input('REKOR_KEY');
const REQUIRE_EXTERNAL = flag('REQUIRE_EXTERNAL');
const WANT_COMMENT = flag('COMMENT', true);
const WANT_SUMMARY = flag('SUMMARY', true);
const FAIL_ON_VIOLATION = flag('FAIL_ON_VIOLATION', true);
const VERSION = input('VERSION') || 'latest';
const BIN = input('BIN');
const TOKEN = input('GITHUB_TOKEN');
const API = (input('GITHUB_API_URL') || 'https://api.github.com').replace(/\/+$/, '');

const log = (msg) => console.log(msg);
const notice = (msg) => console.log(`::notice::${msg}`);
const warn = (msg) => console.log(`::warning::${msg}`);
const fail = (msg) => {
  console.log(`::error::${msg}`);
  process.exit(1);
};

if (!EVIDENCE) fail('`evidence` is required: a .tgev path or a stored run id.');
if (!POLICY) fail('`policy` is required: a path to a guardrail policy JSON file.');
if (!existsSync(POLICY)) fail(`Policy file not found: ${POLICY}`);
if (REQUIRE_EXTERNAL && !ANCHORS) fail('`require-external` needs `anchors` to be set.');
if (ANCHORS && !existsSync(ANCHORS)) fail(`Anchors file not found: ${ANCHORS}`);

/* ------------------------------------------------------------------ */
/* running the CLI                                                     */
/* ------------------------------------------------------------------ */

/**
 * Resolve how to invoke traceglass.
 *
 * `bin` wins so a repo that already built the CLI does not pay for a network
 * install, and so this action can be exercised end to end without publishing.
 */
function cliInvocation() {
  if (BIN) {
    if (!existsSync(BIN)) fail(`\`bin\` was set to ${BIN}, which does not exist.`);
    return { command: process.execPath, prefix: [BIN], label: `node ${BIN}` };
  }
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  return {
    command: npx,
    prefix: ['--yes', `traceglass@${VERSION}`],
    label: `npx traceglass@${VERSION}`,
  };
}

const CLI = cliInvocation();

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(CLI.command, [...CLI.prefix, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      // npx on Windows is a .cmd shim, which needs a shell to execute.
      shell: process.platform === 'win32' && !BIN,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', (e) => resolve({ code: -1, stdout, stderr: String(e) }));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

/** Parse CLI JSON, failing loudly rather than posting a half-empty comment. */
function parseJson(what, { code, stdout, stderr }) {
  const text = stdout.trim();
  if (!text) {
    fail(`\`traceglass ${what}\` produced no output (exit ${code}). ${stderr.trim()}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail(
      `\`traceglass ${what}\` did not return JSON (exit ${code}). ` +
        `First 400 characters: ${text.slice(0, 400)}`,
    );
  }
}

/* ------------------------------------------------------------------ */
/* the check                                                           */
/* ------------------------------------------------------------------ */

log(`traceglass: ${CLI.label}`);
log(`evidence:   ${EVIDENCE}`);
log(`policy:     ${POLICY}`);

const checkRun = await runCli(['check', EVIDENCE, '--policy', POLICY, '--json']);
// `check` exits 1 on a violation, which is the normal path here — only a
// missing file or a broken invocation gives us nothing to parse.
const check = parseJson('check', checkRun);

let anchor = null;
let anchorFileProblems = [];
let anchorFailedGate = false;
if (ANCHORS) {
  const args = ['verify', EVIDENCE, '--json', '--anchors', ANCHORS];
  if (TSA_CERT) args.push('--tsa-cert', TSA_CERT);
  if (REKOR_KEY) args.push('--rekor-key', REKOR_KEY);
  if (REQUIRE_EXTERNAL) args.push('--require-external');
  const verifyRun = await runCli(args);
  const verify = parseJson('verify', verifyRun);
  anchor = verify.anchor ?? null;
  anchorFileProblems = verify.anchorsFile?.problems ?? [];
  // `verify --require-external` folds the gate into its own exit code and
  // `ok` field; carry that into the action's verdict.
  anchorFailedGate = verify.ok === false;
}

const ok = check.ok === true && !anchorFailedGate;
const violations = check.policy?.violations ?? [];

const markdown = renderMarkdown({
  check,
  anchor,
  anchorFileProblems,
  evidence: EVIDENCE,
  policyPath: POLICY,
  runUrl:
    process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
      ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
      : null,
});

/* ------------------------------------------------------------------ */
/* artefacts + outputs                                                 */
/* ------------------------------------------------------------------ */

const artefactDir = mkdtempSync(join(tmpdir(), 'traceglass-action-'));
const reportPath = join(artefactDir, 'traceglass-report.md');
const jsonPath = join(artefactDir, 'traceglass-check.json');
writeFileSync(reportPath, markdown);
writeFileSync(jsonPath, JSON.stringify({ check, ...(anchor ? { anchor } : {}) }, null, 2) + '\n');

/** Multi-line-safe `$GITHUB_OUTPUT` write (heredoc form). */
function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  const text = String(value);
  if (!file) {
    log(`output ${name}=${text}`);
    return;
  }
  if (text.includes('\n')) {
    const delim = `ghadelim_${Math.random().toString(36).slice(2)}`;
    appendFileSync(file, `${name}<<${delim}\n${text}\n${delim}\n`);
  } else {
    appendFileSync(file, `${name}=${text}\n`);
  }
}

setOutput('ok', ok ? 'true' : 'false');
setOutput('violations', String(violations.length));
setOutput('run-id', check.runId ?? '');
setOutput('anchor-strength', anchor?.strength ?? '');
setOutput('report', reportPath);
setOutput('json', jsonPath);

if (WANT_SUMMARY && process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + '\n');
}

log('');
log(markdown);

/* ------------------------------------------------------------------ */
/* the pull-request comment                                            */
/* ------------------------------------------------------------------ */

/** The PR this job is running for, or null when there is not one. */
function pullRequestNumber() {
  const path = process.env.GITHUB_EVENT_PATH;
  if (!path || !existsSync(path)) return null;
  let event;
  try {
    event = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
  const n = event.pull_request?.number ?? event.issue?.number;
  return typeof n === 'number' ? n : null;
}

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: {
      accept: 'application/vnd.github+json',
      authorization: `Bearer ${TOKEN}`,
      'content-type': 'application/json',
      'x-github-api-version': '2022-11-28',
      'user-agent': 'traceglass-action',
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${method} ${url} -> ${res.status} ${res.statusText}: ${text.slice(0, 300)}`);
  }
  return text ? JSON.parse(text) : null;
}

if (WANT_COMMENT) {
  const pr = pullRequestNumber();
  const repo = process.env.GITHUB_REPOSITORY;
  if (!pr || !repo) {
    notice('No pull request in this event; skipping the comment.');
  } else if (!TOKEN) {
    warn('`comment` is on but no `github-token` was supplied; skipping the comment.');
  } else {
    const marker = markerFor(`${EVIDENCE}|${POLICY}`);
    const body = `${marker}\n${markdown}`;
    const base = `${API}/repos/${repo}/issues/${pr}/comments`;
    try {
      // Paginate: a long-lived PR can push our comment past the first page.
      let existing = null;
      for (let page = 1; page <= 10 && !existing; page++) {
        const batch = await api('GET', `${base}?per_page=100&page=${page}`);
        if (!Array.isArray(batch) || batch.length === 0) break;
        existing = batch.find((c) => typeof c.body === 'string' && c.body.includes(marker));
        if (batch.length < 100) break;
      }
      if (existing) {
        await api('PATCH', `${API}/repos/${repo}/issues/comments/${existing.id}`, { body });
        log(`Updated pull-request comment #${existing.id}.`);
      } else {
        const created = await api('POST', base, { body });
        log(`Posted pull-request comment #${created?.id}.`);
      }
    } catch (e) {
      // A missing `pull-requests: write` permission must not silently turn a
      // failing policy check into a passing job, so warn and carry on to the
      // exit code below rather than throwing.
      warn(`Could not post the pull-request comment: ${e.message}`);
    }
  }
}

/* ------------------------------------------------------------------ */
/* verdict                                                             */
/* ------------------------------------------------------------------ */

if (ok) {
  notice(`traceglass: ${check.runId ?? EVIDENCE} passed integrity and policy.`);
  process.exit(0);
}

const reasons = [];
if (check.integrity?.ok === false) reasons.push('integrity check failed');
if (violations.length) reasons.push(`${violations.length} policy violation(s)`);
if (anchorFailedGate) reasons.push('anchor requirement not met');
const why = reasons.join(', ') || 'the record did not pass';

if (FAIL_ON_VIOLATION) {
  console.log(`::error::traceglass: ${why}.`);
  process.exit(1);
}
warn(`traceglass: ${why}. Not failing the build (fail-on-violation: false).`);
process.exit(0);
