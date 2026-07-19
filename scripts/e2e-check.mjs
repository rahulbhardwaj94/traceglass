#!/usr/bin/env node
/**
 * v0.3 outcome check — exercises the REAL built CLI end-to-end in throwaway
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
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'packages/cli/dist/bin.js');
const sdk = join(root, 'packages/sdk/dist/index.js');
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

console.log('\ntraceglass outcome check (v0.3 evidence + v0.4 governance)\n');

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
    import { startRecording } from ${JSON.stringify(sdk)};
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
    execFileSync('node', ['-e', `
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
    `], { encoding: 'utf8' });
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
check('anchor --all writes idempotent anchor records', () => {
  const anchorsFile = join(out, 'anchors.jsonl');
  cli(['anchor', '--all', '-o', anchorsFile]);
  const first = readFileSync(anchorsFile, 'utf8').trim().split('\n').length;
  cli(['anchor', '--all', '-o', anchorsFile]); // second run adds nothing
  const second = readFileSync(anchorsFile, 'utf8').trim().split('\n').length;
  assert(first >= 1, 'no anchors written');
  assert(first === second, `not idempotent: ${first} → ${second}`);
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

for (const dir of [home, cleanHome, out]) rmSync(dir, { recursive: true, force: true });

console.log(
  failures === 0
    ? '\nPASS — every guarantee held: capture, sign, collect, export, verify, tamper-detect.\n'
    : `\nFAIL — ${failures} check(s) failed.\n`,
);
process.exit(failures === 0 ? 0 : 1);
