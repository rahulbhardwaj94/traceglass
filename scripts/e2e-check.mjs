#!/usr/bin/env node
/**
 * traceglass outcome check — exercises the REAL built CLI end-to-end in throwaway
 * homes. Run after `npm run build`:
 *
 *   node scripts/e2e-check.mjs
 *
 * Proves: keygen → SDK live-record (signed) → verify (chain + signature) →
 * serve collector with token auth (200 / 401) → export → offline verify in an
 * empty home → tamper detection → anchoring. Prints PASS/FAIL per check and
 * exits 1 if any check fails.
 */
import { execFileSync, spawn } from 'node:child_process';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'packages/cli/dist/bin.js');
const sdk = join(root, 'packages/sdk/dist/index.js');
// ESM specifiers must be file:// URLs when absolute: on Windows a bare
// "D:\\a\\..." path is read as protocol 'd:' and the loader refuses it.
// Every generated child script below imports through this, not `sdk`.
const sdkSpecifier = JSON.stringify(pathToFileURL(sdk).href);
const nativeFixture = join(root, 'fixtures/sample-run-native.json');

const home = mkdtempSync(join(tmpdir(), 'tg-check-'));
const cleanHome = mkdtempSync(join(tmpdir(), 'tg-check-clean-'));
const out = mkdtempSync(join(tmpdir(), 'tg-check-out-'));

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
  } catch (e) {
    failures += 1;
    console.log(`  ❌ ${name}\n     ${String(e.message ?? e).split('\n')[0]}`);
  }
}
function cli(args, opts = {}) {
  return execFileSync('node', [bin, ...args], {
    encoding: 'utf8',
    env: { ...process.env, TRACEGLASS_HOME: opts.home ?? home },
  });
}
function cliFails(args, opts = {}) {
  try {
    cli(args, opts);
  } catch (e) {
    return { code: e.status, output: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
  throw new Error('expected non-zero exit, got success');
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

console.log('\ntraceglass outcome check (evidence + governance + watch)\n');

if (!existsSync(bin) || !existsSync(sdk)) {
  console.error('  Build first: npm run build');
  process.exit(1);
}

// 1. keygen
check('keygen generates a signing key', () => {
  const output = cli(['keygen']);
  assert(/keyId [0-9a-f]{16}/.test(output), `no keyId in: ${output}`);
});

// 2. SDK live-record a run (child process using the built SDK)
let runId = '';
check('SDK records a live run into the store', () => {
  const script = `
    import { startRecording } from ${sdkSpecifier};
    const rec = startRecording({ name: 'outcome-check agent', id: 'check-run' });
    rec.step({ type: 'user_input', label: 'Dun account 4471', input: { account: '4471' } });
    rec.step({ type: 'tool_call', toolName: 'get_payment_status', label: 'Tool: get_payment_status',
      output: { status: 'overdue' }, dataPayload: { status: 'overdue' }, tokens: 800, cost: 0.4 });
    rec.step({ type: 'final_output', label: 'Done', output: 'Reminder sent.' });
    const run = await rec.end();
    console.log(run.id);
  `;
  const file = join(out, 'record.mjs');
  writeFileSync(file, script);
  const output = execFileSync('node', [file], {
    encoding: 'utf8',
    env: { ...process.env, TRACEGLASS_HOME: home },
  });
  runId = output.trim();
  assert(runId === 'check-run', `unexpected run id: ${runId}`);
  assert(cli(['list']).includes('check-run'), 'run not in `traceglass list`');
});

// 3. verify: chain + signature
check('verify reports chain intact AND signature OK', () => {
  const output = cli(['verify', runId]);
  assert(output.includes('chain intact'), 'chain not intact');
  assert(/Signature OK \(keyId [0-9a-f]{16}\)/.test(output), `unsigned or invalid: ${output}`);
});

// 4. serve: token-authenticated collector
check('serve ingests with the right token (200) and rejects a wrong one (401)', () => {
  const server = spawn('node', [bin, 'serve', '--port', '43180', '--token', 't0ken'], {
    env: { ...process.env, TRACEGLASS_HOME: home },
    stdio: 'ignore',
  });
  try {
    execFileSync(
      'node',
      [
        '-e',
        `
      const body = require('fs').readFileSync(${JSON.stringify(nativeFixture)}, 'utf8');
      async function main() {
        for (let i = 0; i < 40; i++) {
          try { await fetch('http://127.0.0.1:43180/api/runs'); break; }
          catch { await new Promise(r => setTimeout(r, 250)); }
        }
        const ok = await fetch('http://127.0.0.1:43180/api/ingest', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: 'Bearer t0ken' },
          body,
        });
        if (ok.status !== 200) throw new Error('expected 200, got ' + ok.status);
        const bad = await fetch('http://127.0.0.1:43180/api/ingest', {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: 'Bearer nope' },
          body,
        });
        if (bad.status !== 401) throw new Error('expected 401, got ' + bad.status);
      }
      main().then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); });
    `,
      ],
      { encoding: 'utf8' },
    );
  } finally {
    server.kill('SIGTERM');
  }
});

// 5. refuse non-loopback bind without a token
check('serve refuses --host 0.0.0.0 without a token', () => {
  const { code, output } = cliFails(['serve', '--host', '0.0.0.0', '--port', '43181']);
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(/Refusing to bind/.test(output), `wrong error: ${output}`);
});

// 6. export
const evidenceFile = join(out, 'check-run.tgev');
check('export writes a signed .tgev evidence file', () => {
  const output = cli(['export', runId, '-o', evidenceFile]);
  assert(output.includes('signed:  yes'), `not signed: ${output}`);
  assert(existsSync(evidenceFile), 'evidence file missing');
});

// 7. offline verify in an empty home (no store, no keys)
check('evidence verifies OFFLINE in a clean home (exit 0)', () => {
  const output = cli(['verify', evidenceFile], { home: cleanHome });
  assert(output.includes('chain intact'), 'chain not intact offline');
  assert(/Signature OK/.test(output), 'signature not verified offline');
});

// 8. tamper with one byte → verify fails naming the step
check('a tampered evidence file fails verification (exit 1, names the step)', () => {
  const envelope = JSON.parse(readFileSync(evidenceFile, 'utf8'));
  envelope.run.steps[1].output.status = 'paid'; // rewrite history
  const tamperedFile = join(out, 'tampered.tgev');
  writeFileSync(tamperedFile, JSON.stringify(envelope));
  const { code, output } = cliFails(['verify', tamperedFile], { home: cleanHome });
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(/step #1/.test(output), `did not name step #1: ${output}`);
});

// 9. anchors
const anchorsFile = join(out, 'anchors.jsonl');
check('anchor --all writes idempotent anchor records', () => {
  cli(['anchor', '--all', '-o', anchorsFile]);
  const first = readFileSync(anchorsFile, 'utf8').trim().split('\n').length;
  cli(['anchor', '--all', '-o', anchorsFile]); // second run adds nothing
  const second = readFileSync(anchorsFile, 'utf8').trim().split('\n').length;
  assert(first >= 1, 'no anchors written');
  assert(first === second, `not idempotent: ${first} → ${second}`);
});

// 9a. the loop that anchoring exists for: a stored anchor is checked back.
check('anchor --verify confirms stored runs against their anchors', () => {
  const output = cli(['anchor', '--verify', '-o', anchorsFile]);
  assert(/File integrity OK/.test(output), `chain not reported intact: ${output}`);
  assert(new RegExp(`✓ ${runId}`).test(output), `run not verified: ${output}`);
});

check('verify --anchors reports the anchor alongside the chain and signature', () => {
  const output = cli(['verify', runId, '--anchors', anchorsFile]);
  assert(/Anchor: LOCAL only/.test(output), `no anchor verdict: ${output}`);
});

check('verify --require-external fails on a local-only anchor (exit 1)', () => {
  // The honesty gate: a file-sink anchor must never be reported as third-party
  // proof, and CI must be able to demand a real trust root.
  const { code, output } = cliFails([
    'verify',
    runId,
    '--anchors',
    anchorsFile,
    '--require-external',
  ]);
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(/not bound to out-of-band trust material/.test(output), `wrong reason: ${output}`);
});

check('a hand-written anchor line is detected (chain break + unknown run)', () => {
  const forgedFile = join(out, 'forged-anchors.jsonl');
  writeFileSync(forgedFile, readFileSync(anchorsFile, 'utf8'));
  appendFileSync(
    forgedFile,
    JSON.stringify({
      version: 2,
      runId: 'run-that-never-happened',
      runHash: 'f'.repeat(64),
      anchoredAt: '2026-01-01T00:00:00.000Z',
    }) + '\n',
  );
  const { code, output } = cliFails(['anchor', '--verify', '-o', forgedFile]);
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(/FILE INTEGRITY FAILED/.test(output), `chain break not reported: ${output}`);
  assert(/NO SUCH RUN is stored/.test(output), `fabricated run not reported: ${output}`);
});

check('anchoring refuses to reach the network without an explicit URL', () => {
  // Zero egress by default is a stated product guarantee; these two flags are
  // the only doors to it, and both must stay shut unless the operator opens one.
  const tsa = cliFails(['anchor', '--all', '--sink', 'rfc3161', '-o', join(out, 'x.jsonl')]);
  assert(tsa.code === 1 && /needs --tsa/.test(tsa.output), `TSA guard: ${tsa.output}`);
  const rekor = cliFails([
    'anchor',
    '--all',
    '--sink',
    'rekor',
    '--rekor',
    'https://example.invalid',
    '-o',
    join(out, 'x.jsonl'),
  ]);
  assert(
    rekor.code === 1 && /i-understand-public-log/.test(rekor.output),
    `public-log consent guard: ${rekor.output}`,
  );
});

check('a failed external anchor still records the run and exits 1', () => {
  // Never lose evidence because a timestamp service was unreachable, and never
  // mark something anchored that is not.
  const offlineFile = join(out, 'offline-anchors.jsonl');
  const { code, output } = cliFails([
    'anchor',
    '--all',
    '--sink',
    'rfc3161',
    '--tsa',
    'http://127.0.0.1:1', // connection refused, immediately
    '--timeout',
    '2000',
    '-o',
    offlineFile,
  ]);
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(/NOT externally anchored/.test(output), `failure not reported: ${output}`);
  assert(/No evidence was lost/.test(output), `no reassurance about the record: ${output}`);
  // --all covers every stored run, so find ours rather than assuming line 1.
  const written = readFileSync(offlineFile, 'utf8')
    .trim()
    .split('\n')
    .map((l) => JSON.parse(l));
  const mine = written.find((r) => r.runId === runId);
  assert(mine !== undefined, 'the run was NOT recorded locally after the TSA failed');
  assert(
    written.every((r) => r.proof === undefined),
    'a record was marked anchored without a valid proof',
  );
});

// 10. report from evidence alone (with the v0.4 compliance summary)
check('report renders from the evidence file alone, with a compliance summary', () => {
  const reportFile = join(out, 'audit.html');
  cli(['report', evidenceFile, '-o', reportFile], { home: cleanHome });
  const html = readFileSync(reportFile, 'utf8');
  assert(html.includes('<!doctype html>'), 'no HTML report');
  assert(html.includes('Compliance summary'), 'compliance summary section missing');
});

// 11. verify --json for CI
check('verify --json emits machine-readable ok:true', () => {
  const parsed = JSON.parse(cli(['verify', runId, '--json']));
  assert(parsed.ok === true, `expected ok:true, got ${JSON.stringify(parsed).slice(0, 120)}`);
  assert(parsed.chain.ok === true && parsed.signature.ok === true, 'chain/signature not ok');
});

// 12. policy check: pass
check('check passes a satisfied guardrail policy (exit 0)', () => {
  const policyFile = join(out, 'policy-pass.json');
  writeFileSync(
    policyFile,
    JSON.stringify({
      name: 'sane limits',
      rules: { maxCostPerRun: 100, requireSignature: true, forbidWarnings: ['loop'] },
    }),
  );
  const output = cli(['check', runId, '--policy', policyFile]);
  assert(/Policy .*PASS/.test(output), `no PASS verdict: ${output}`);
});

// 13. policy check: fail names the violated rule, exit 1
check('check fails an unmet policy (exit 1, names the rule)', () => {
  const policyFile = join(out, 'policy-fail.json');
  writeFileSync(
    policyFile,
    JSON.stringify({
      name: 'approval required',
      rules: { requireApprovalFor: ['get_payment_status'], maxCostPerRun: 0.01 },
    }),
  );
  const { code, output } = cliFails(['check', runId, '--policy', policyFile]);
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(output.includes('requireApprovalFor'), `rule not named: ${output}`);
  assert(output.includes('maxCostPerRun'), `second rule not named: ${output}`);
});

// 14. cross-run search
check('search finds the account across stored runs', () => {
  const output = cli(['search', '4471']);
  assert(output.includes('check-run'), `run not found in: ${output}`);
  assert(output.includes('hit(s)'), 'no hit summary');
});

// 14b. tail: a recording is visible LIVE, mid-flight
check('tail sees an in-progress recording and its warnings before it ends', () => {
  const tailHome = join(out, 'tail-home');
  mkdirSync(tailHome, { recursive: true });
  cli(['keygen'], { home: tailHome });
  const agent = join(out, 'slow-agent.mjs');
  writeFileSync(
    agent,
    `import { startRecording } from ${sdkSpecifier};
     const sleep = (ms) => new Promise(r => setTimeout(r, ms));
     const rec = startRecording({ name: 'slow agent', id: 'tail-run' });
     rec.step({ type: 'user_input', label: 'start' });
     for (let i = 0; i < 3; i++) {
       rec.step({ type: 'tool_call', toolName: 'get_status', label: 'Tool: get_status', cost: 1 });
       await sleep(800);
     }
     await rec.end();`,
  );
  const proc = spawn('node', [agent], {
    env: { ...process.env, TRACEGLASS_HOME: tailHome },
    stdio: 'ignore',
  });
  try {
    // Poll for the recording rather than sleeping a fixed interval: node
    // startup plus module load can outlast any constant we pick on a slow
    // runner, and a fixed wait turns that into an intermittent red build.
    let listed = '';
    for (let i = 0; i < 40; i++) {
      try {
        listed = cli(['tail', '--list'], { home: tailHome });
        if (/tail-run/.test(listed)) break;
      } catch {
        /* the recording may not exist yet — keep waiting */
      }
      execFileSync('node', ['-e', 'setTimeout(()=>{},100)'], { encoding: 'utf8' });
    }
    assert(/tail-run/.test(listed), `live recording not listed: ${listed}`);

    // Follow it to completion; the loop warning must appear mid-flight.
    const tailed = cli(['tail', 'tail-run', '--interval', '150'], { home: tailHome });
    assert(/LOOP/.test(tailed), `loop warning never fired live: ${tailed}`);
    assert(/run completed/.test(tailed), `no finalize handoff: ${tailed}`);
    assert(/signed/.test(tailed), `finalized run not signed: ${tailed}`);
  } finally {
    proc.kill('SIGTERM');
  }
});

// 15a. redaction: PII destroyed, anchor + signature survive
check('redact removes PII while the anchor and signature stay valid', () => {
  const redactHome = join(out, 'redact-home');
  mkdirSync(redactHome, { recursive: true });
  cli(['keygen'], { home: redactHome });
  const recFile = join(out, 'record-pii.mjs');
  writeFileSync(
    recFile,
    `import { startRecording } from ${sdkSpecifier};
     const rec = startRecording({ name: 'pii', id: 'pii-run' });
     rec.step({ type: 'user_input', label: 'Lookup', input: { ssn: '123-45-6789', keep: 'visible' } });
     await rec.end();`,
  );
  execFileSync('node', [recFile], {
    encoding: 'utf8',
    env: { ...process.env, TRACEGLASS_HOME: redactHome },
  });

  const db = join(redactHome, 'traceglass.sqlite');
  assert(readFileSync(db, 'latin1').includes('123-45-6789'), 'PII not present before redaction');
  const anchorBefore = cli(['verify', 'pii-run'], { home: redactHome }).match(/runHash: (\w+)/)[1];

  // Dry run must NOT change anything.
  const dry = cli(['redact', 'pii-run', '--path', 'input.ssn'], { home: redactHome });
  assert(/DRY RUN/.test(dry), `expected a dry run: ${dry}`);
  assert(readFileSync(db, 'latin1').includes('123-45-6789'), 'dry run destroyed data!');

  cli(['redact', 'pii-run', '--path', 'input.ssn', '--reason', 'erasure', '--yes'], {
    home: redactHome,
  });
  const after = readFileSync(db, 'latin1');
  assert(!after.includes('123-45-6789'), 'PII still on disk after redaction');
  assert(after.includes('visible'), 'sibling value was destroyed too');

  const verifyOut = cli(['verify', 'pii-run'], { home: redactHome });
  const anchorAfter = verifyOut.match(/runHash: (\w+)/)[1];
  assert(anchorAfter === anchorBefore, `anchor changed: ${anchorBefore} -> ${anchorAfter}`);
  assert(/chain intact/.test(verifyOut), 'chain broken after redaction');
  assert(/Signature OK/.test(verifyOut), 'original signature no longer validates');
});

// 15b. redaction is visible to an auditor in the report
check('the audit report discloses what was redacted', () => {
  const redactHome = join(out, 'redact-home');
  const reportFile = join(out, 'redacted.html');
  cli(['report', 'pii-run', '-o', reportFile], { home: redactHome });
  const html = readFileSync(reportFile, 'utf8');
  assert(html.includes('Data minimisation'), 'no data-minimisation row');
  assert(html.includes('input.ssn'), 'redacted path not disclosed');
});

// 16. watch --once: auto-record a Claude Code session as signed evidence
check('watch --once records a settled Claude Code session (signed, idempotent)', () => {
  const sessions = join(out, 'watch-sessions/-proj');
  mkdirSync(sessions, { recursive: true });
  const sessFile = join(sessions, 'sess-watch.jsonl');
  writeFileSync(sessFile, readFileSync(join(root, 'fixtures/sample-claude-code-session.jsonl')));
  // Age the file past any settle window.
  const old = new Date(Date.now() - 3600_000);
  utimesSync(sessFile, old, old);

  const output = cli(['watch', '--once', '--dir', join(out, 'watch-sessions'), '--settle', '0']);
  assert(/1 session\(s\) recorded/.test(output), `no ingest: ${output}`);
  const verifyOut = cli(['verify', 'cc-sess-abc']);
  assert(/Signature OK/.test(verifyOut), `watch run not signed: ${verifyOut}`);

  const again = cli(['watch', '--once', '--dir', join(out, 'watch-sessions'), '--settle', '0']);
  assert(/0 session\(s\) recorded/.test(again), `not idempotent: ${again}`);
});

// 17. watch --once with a violated policy exits 1 and audit-logs it
check('watch --once fails the sweep on a policy violation (exit 1, audited)', () => {
  const policyFile = join(out, 'watch-policy.json');
  writeFileSync(
    policyFile,
    JSON.stringify({ name: 'coding guardrails', rules: { forbidTools: ['get_payment_status'] } }),
  );
  // Fresh home so the session ingests again under this policy.
  const watchHome = join(out, 'watch-home-2');
  const { code, output } = cliFails(
    [
      'watch',
      '--once',
      '--dir',
      join(out, 'watch-sessions'),
      '--settle',
      '0',
      '--policy',
      policyFile,
    ],
    { home: watchHome },
  );
  assert(code === 1, `expected exit 1, got ${code}`);
  assert(/policy FAIL/.test(output), `no FAIL verdict: ${output}`);
  const audit = readFileSync(join(watchHome, 'audit.jsonl'), 'utf8');
  assert(audit.includes('policy-violation'), 'violation not audit-logged');
});

for (const dir of [home, cleanHome, out]) rmSync(dir, { recursive: true, force: true });

console.log(
  failures === 0
    ? '\nPASS — every guarantee held: capture, sign, collect, export, verify, tamper-detect.\n'
    : `\nFAIL — ${failures} check(s) failed.\n`,
);
process.exit(failures === 0 ? 0 : 1);
