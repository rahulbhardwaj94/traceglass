/**
 * Runs the forensic walkthrough end to end and writes the transcript that
 * docs/forensic-walkthrough.md quotes.
 *
 *   npm run build
 *   node docs/examples/walkthrough.mjs
 *
 * Every command in that document comes out of here. If a command stops working
 * the transcript stops regenerating, which is the point: documentation about an
 * evidence product should not be able to drift from the product.
 *
 * It is hermetic. TRACEGLASS_HOME points at a scratch directory under the OS
 * temp dir, so it never touches ~/.traceglass and leaves nothing in the repo,
 * and it makes no network request — the anchor step uses the default local
 * file sink. The transcript path is printed at the end.
 */
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
const WORK = join(tmpdir(), 'traceglass-walkthrough');
const HOME = join(WORK, 'home');
const THIRD_PARTY_HOME = join(WORK, 'third-party-home');
const OUT = join(WORK, 'out');
const CLI = join(REPO, 'packages', 'cli', 'dist', 'bin.js');
const RUN_ID = 'collections-4471';

if (!existsSync(CLI)) {
  console.error(`No built CLI at ${CLI}. Run \`npm run build\` first.`);
  process.exit(1);
}

rmSync(WORK, { recursive: true, force: true });
mkdirSync(HOME, { recursive: true });
mkdirSync(THIRD_PARTY_HOME, { recursive: true });
mkdirSync(OUT, { recursive: true });

const transcript = [];

/** Run a command to completion, capturing merged stdout/stderr. */
function run(argv, { env = {}, display, cwd = REPO, expectExit } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, argv, {
      cwd,
      env: { ...process.env, TRACEGLASS_HOME: HOME, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', (code) => {
      const shown = display ?? toDisplay(argv, env);
      transcript.push({ command: shown, output: out.trimEnd(), exitCode: code });
      console.log(`\n$ ${shown}`);
      if (out.trim()) console.log(out.trimEnd());
      console.log(`[exit ${code}]`);
      if (expectExit !== undefined && code !== expectExit) {
        console.error(`  !! expected exit ${expectExit}, got ${code}`);
        process.exitCode = 1;
      }
      resolvePromise({ code, out });
    });
  });
}

/** Render an argv as the command a reader would actually type. */
function toDisplay(argv, env) {
  const prefix = Object.entries(env)
    .map(([k, v]) => `${k}=${v.replace(WORK, '/tmp/tg')} `)
    .join('');
  const quote = (a) => (/[\s"]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a);
  const rest = argv.map((a) => quote(a.replace(REPO + '/', '').replace(WORK, '/tmp/tg')));
  if (rest[0] === CLI || rest[0] === 'packages/cli/dist/bin.js') {
    return prefix + 'traceglass ' + rest.slice(1).join(' ');
  }
  return prefix + 'node ' + rest.join(' ');
}

const tg = (...args) => [CLI, ...args];

/** Poll for a condition instead of sleeping — no fixed timeouts anywhere. */
async function until(predicate, { timeoutMs = 30000, everyMs = 50, what = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, everyMs));
  }
  throw new Error(`timed out waiting for ${what}`);
}

// ---------------------------------------------------------------------------
console.log('=== 1. keys ===');
await run(tg('keygen'), { expectExit: 0 });

// ---------------------------------------------------------------------------
console.log('\n=== 2. record + tail (concurrent) ===');
const agentArgs = [join(HERE, 'collections-agent.mjs'), RUN_ID, '--delay', '600'];
const agent = spawn(process.execPath, agentArgs, {
  cwd: REPO,
  env: { ...process.env, TRACEGLASS_HOME: HOME },
  stdio: ['ignore', 'pipe', 'pipe'],
});
let agentOut = '';
agent.stdout.on('data', (d) => (agentOut += d));
agent.stderr.on('data', (d) => (agentOut += d));
// Attach the close listener NOW: if the agent finishes while `tail` is still
// running, a listener added afterwards never fires and the await hangs.
const agentDone = new Promise((r) => agent.on('close', r));

// Wait for the journal to exist rather than sleeping a fixed amount.
const journalDir = join(HOME, 'journal');
await until(() => existsSync(journalDir) && readdirSync(journalDir).length > 0, {
  what: 'the recorder to open its journal',
});

await run(tg('tail', RUN_ID), {
  display: `traceglass tail ${RUN_ID}`,
  expectExit: 0,
});

await agentDone;
transcript.push({
  command: `node docs/examples/collections-agent.mjs ${RUN_ID} --delay 600`,
  output: agentOut.trimEnd(),
  exitCode: 0,
  note: 'ran concurrently with the tail above',
});
console.log('\n(agent process output)');
console.log(agentOut.trimEnd());

// ---------------------------------------------------------------------------
console.log('\n=== 3. verify + policy ===');
await run(tg('verify', RUN_ID), { expectExit: 0 });
await run(tg('check', RUN_ID, '--policy', 'docs/examples/collections-policy.json'), {
  expectExit: 1,
});
await run(tg('check', RUN_ID, '--policy', 'docs/examples/collections-policy.json', '--json'), {
  expectExit: 1,
});

// ---------------------------------------------------------------------------
console.log('\n=== 4. anchor, and what a local anchor is worth ===');
const anchors = join(OUT, 'anchors.jsonl');
await run(tg('anchor', RUN_ID, '-o', anchors), { expectExit: 0 });
await run(tg('verify', RUN_ID, '--anchors', anchors), { expectExit: 0 });
await run(tg('verify', RUN_ID, '--anchors', anchors, '--require-external'), { expectExit: 1 });

// ---------------------------------------------------------------------------
console.log('\n=== 5. the subject exercises erasure ===');
await run(tg('search', 'priya.nair@example.com'), { expectExit: 0 });
await run(
  tg('redact', RUN_ID, '--pattern', 'email', '--path', 'input.customer.phone', '--path',
     'input.customer.pan', '--reason', 'Art. 17 erasure request, ticket DSR-2291'),
  { expectExit: 0 },
);
await run(
  tg('redact', RUN_ID, '--pattern', 'email', '--path', 'input.customer.phone', '--path',
     'input.customer.pan', '--reason', 'Art. 17 erasure request, ticket DSR-2291', '--yes'),
  { expectExit: 0 },
);
await run(tg('verify', RUN_ID), { expectExit: 0 });
await run(tg('verify', RUN_ID, '--json'), { expectExit: 0 });
await run(tg('search', 'priya.nair@example.com'), { expectExit: 0 });
await run(tg('vacuum'), { expectExit: 0 });

// ---------------------------------------------------------------------------
console.log('\n=== 6. export and verify as a third party ===');
const tgev = join(OUT, 'account-4471.tgev');
await run(tg('export', RUN_ID, '-o', tgev), { expectExit: 0 });
await run(tg('verify', tgev), { env: { TRACEGLASS_HOME: THIRD_PARTY_HOME }, expectExit: 0 });
await run(tg('check', tgev, '--policy', 'docs/examples/collections-policy.json'), {
  env: { TRACEGLASS_HOME: THIRD_PARTY_HOME },
  expectExit: 1,
});
await run(tg('report', tgev, '-o', join(OUT, 'audit.html')), {
  env: { TRACEGLASS_HOME: THIRD_PARTY_HOME },
  expectExit: 0,
});

// ---------------------------------------------------------------------------
console.log('\n=== 7. tamper, and be caught ===');
// Restate the refund as a hundredth of its real size — the single edit a
// dishonest holder of this file would most want to make.
const tampered = join(OUT, 'account-4471-tampered.tgev');
const original = readFileSync(tgev, 'utf8');
if (!original.includes('"amount": 18400')) throw new Error('tamper target not found in the export');
writeFileSync(tampered, original.replace('"amount": 18400', '"amount": 184'));
await run(tg('verify', tampered), { env: { TRACEGLASS_HOME: THIRD_PARTY_HOME }, expectExit: 1 });

// ---------------------------------------------------------------------------
writeFileSync(join(WORK, 'transcript.json'), JSON.stringify(transcript, null, 2) + '\n');
const text = transcript
  .map(
    (t) =>
      `$ ${t.command}\n${t.output}\n[exit ${t.exitCode}]${t.note ? `\n(${t.note})` : ''}\n`,
  )
  .join('\n');
writeFileSync(join(WORK, 'transcript.txt'), text);
console.log(`\nwrote ${join(WORK, 'transcript.txt')}`);
console.log(process.exitCode ? 'SOME STEPS DID NOT EXIT AS EXPECTED' : 'all steps exited as expected');
