/**
 * Runs the commands quoted in docs/recipes/*.md and writes their transcripts.
 *
 *   npm run build
 *   node docs/examples/recipes.mjs
 *
 * Companion to walkthrough.mjs. Same rule: nothing goes in the recipes that has
 * not come out of here. Hermetic (scratch TRACEGLASS_HOME under the OS temp
 * dir) and offline — the only HTTP is to a collector this script starts on
 * loopback and stops again.
 */
import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');
const WORK = join(tmpdir(), 'traceglass-recipes');
const HOME = join(WORK, 'home');
const CLI = join(REPO, 'packages', 'cli', 'dist', 'bin.js');
const PORT = 4319;

if (!existsSync(CLI)) {
  console.error(`No built CLI at ${CLI}. Run \`npm run build\` first.`);
  process.exit(1);
}

rmSync(WORK, { recursive: true, force: true });
mkdirSync(HOME, { recursive: true });

const transcript = [];
const sections = [];
let section = null;
const startSection = (title) => {
  section = { title, entries: [] };
  sections.push(section);
  console.log(`\n\n########## ${title} ##########`);
};

function record(command, output, exitCode, note) {
  const entry = { command, output: output.trimEnd(), exitCode, ...(note ? { note } : {}) };
  transcript.push(entry);
  section?.entries.push(entry);
  console.log(`\n$ ${command}`);
  if (entry.output) console.log(entry.output);
  console.log(`[exit ${exitCode}]`);
}

function quote(a) {
  return /[\s"]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a;
}

function display(argv, env) {
  const scrub = (s) => s.replace(REPO + '/', '').replace(WORK, '/tmp/tg');
  const prefix = Object.entries(env)
    .filter(([k]) => k !== 'TRACEGLASS_HOME')
    .map(([k, v]) => `${k}=${quote(scrub(v))} `)
    .join('');
  const rest = argv.map((a) => quote(scrub(a)));
  if (argv[0] === CLI) return prefix + 'traceglass ' + rest.slice(1).join(' ');
  return prefix + 'node ' + rest.join(' ');
}

function run(argv, { env = {}, expectExit, command } = {}) {
  return new Promise((res) => {
    const child = spawn(process.execPath, argv, {
      cwd: REPO,
      env: { ...process.env, TRACEGLASS_HOME: HOME, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', (code) => {
      record(command ?? display(argv, env), out, code);
      if (expectExit !== undefined && code !== expectExit) {
        console.error(`  !! expected exit ${expectExit}, got ${code}`);
        process.exitCode = 1;
      }
      res({ code, out });
    });
  });
}

function runRaw(command, argv, { expectExit } = {}) {
  return new Promise((res) => {
    const child = spawn(argv[0], argv.slice(1), { cwd: REPO, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (out += d));
    child.on('close', (code) => {
      record(command, out, code);
      if (expectExit !== undefined && code !== expectExit) {
        console.error(`  !! expected exit ${expectExit}, got ${code}`);
        process.exitCode = 1;
      }
      res({ code, out });
    });
  });
}

const tg = (...args) => [CLI, ...args];

async function until(predicate, { timeoutMs = 30000, everyMs = 50, what = 'condition' } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let ok = false;
    try {
      ok = await predicate();
    } catch {
      ok = false;
    }
    if (ok) return true;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, everyMs));
  }
}

/* ================================================================== *
 * Quickstart                                                          *
 * ================================================================== */

startSection('quickstart');

await run(tg('--version'), { expectExit: 0 });
await run(tg('--help'), { expectExit: 0 });

// `demo` starts a dashboard AND opens a browser, so it never returns on its
// own. Start it with --no-open, wait for the URL it prints, then stop it.
{
  const demo = spawn(process.execPath, [CLI, 'demo', '--no-open'], {
    cwd: REPO,
    env: { ...process.env, TRACEGLASS_HOME: join(WORK, 'demo-home') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let demoOut = '';
  demo.stdout.on('data', (d) => (demoOut += d));
  demo.stderr.on('data', (d) => (demoOut += d));
  await until(() => /http:\/\/127\.0\.0\.1:\d+/.test(demoOut), {
    what: 'the demo dashboard to print its URL',
  });
  demo.kill('SIGTERM');
  await new Promise((r) => demo.on('close', r));
  record('traceglass demo', demoOut.trimEnd(), 0, 'runs until Ctrl+C; stopped here after it printed its URL');
}

await run(tg('keygen'), { expectExit: 0 });

/* ================================================================== *
 * Recipe: your own code, via the SDK                                  *
 * ================================================================== */

startSection('sdk');

await run([join(HERE, 'collections-agent.mjs'), 'sdk-demo'], { expectExit: 0 });
await run(tg('verify', 'sdk-demo'), { expectExit: 0 });

// --- crash recovery --------------------------------------------------------
console.log('\n(starting an agent and killing it mid-run)');
const crashing = spawn(process.execPath, [join(HERE, 'collections-agent.mjs'), 'crashed-run', '--delay', '400'], {
  cwd: REPO,
  env: { ...process.env, TRACEGLASS_HOME: HOME },
  stdio: ['ignore', 'pipe', 'pipe'],
});
const journalDir = join(HOME, 'journal');
// Poll the journal for three steps, then SIGKILL — no fixed sleep.
const journalFile = () => {
  if (!existsSync(journalDir)) return null;
  const f = readdirSync(journalDir).find((n) => n.includes('crashed-run'));
  return f ? join(journalDir, f) : null;
};
await until(
  () => {
    const f = journalFile();
    return f !== null && readFileSync(f, 'utf8').split('\n').filter(Boolean).length >= 4;
  },
  { what: 'three steps to be journaled' },
);
crashing.kill('SIGKILL');
await new Promise((r) => crashing.on('close', r));
record('node docs/examples/collections-agent.mjs crashed-run --delay 400', '(killed with SIGKILL mid-run)', 137);

await run(tg('recover'), { expectExit: 0 });
await run(tg('verify', 'crashed-run'), { expectExit: 0 });

/* ================================================================== *
 * Recipe: Claude Code sessions                                        *
 * ================================================================== */

startSection('claude-code');

const projects = join(WORK, 'claude-projects', 'my-repo');
mkdirSync(projects, { recursive: true });
cpSync(
  join(REPO, 'fixtures', 'sample-claude-code-session.jsonl'),
  join(projects, 'sample-claude-code-session.jsonl'),
);

const codingPolicy = join(WORK, 'coding-policy.json');
writeFileSync(
  codingPolicy,
  JSON.stringify(
    { name: 'coding agent guardrails', rules: { forbidInputText: ['.env', 'rm -rf'], maxCostPerRun: 5 } },
    null,
    2,
  ),
);

const sessionsEnv = { CLAUDE_PROJECTS_DIR: join(WORK, 'claude-projects') };
await run(tg('sessions'), { env: sessionsEnv, expectExit: 0 });
const watch = await run(
  tg('watch', '--once', '--dir', join(WORK, 'claude-projects'), '--settle', '0', '--policy', codingPolicy),
);
console.log(`(watch --once exited ${watch.code})`);
await run(tg('list'), { expectExit: 0 });

/* ================================================================== *
 * Recipe: OpenTelemetry + collector mode                              *
 * ================================================================== */

startSection('collector');

const server = spawn(
  process.execPath,
  [CLI, 'serve', '--port', String(PORT), '--token', 'demo-token'],
  { cwd: REPO, env: { ...process.env, TRACEGLASS_HOME: HOME }, stdio: ['ignore', 'pipe', 'pipe'] },
);
let serverOut = '';
server.stdout.on('data', (d) => (serverOut += d));
server.stderr.on('data', (d) => (serverOut += d));

const base = `http://127.0.0.1:${PORT}`;
await until(
  async () => (await fetch(`${base}/api/runs`, { headers: { authorization: 'Bearer demo-token' } })).ok,
  { what: 'the collector to accept requests' },
);
record(`traceglass serve --port ${PORT} --token demo-token`, serverOut.trimEnd(), 0, 'left running in the background');

const otelFixture = join(REPO, 'fixtures', 'sample-run-otel.json');
await runRaw(
  `curl -sS -X POST ${base}/v1/traces -H 'authorization: Bearer demo-token' -H 'content-type: application/json' --data-binary @fixtures/sample-run-otel.json`,
  ['curl', '-sS', '-X', 'POST', `${base}/v1/traces`, '-H', 'authorization: Bearer demo-token',
   '-H', 'content-type: application/json', '--data-binary', `@${otelFixture}`],
  { expectExit: 0 },
);

await runRaw(
  `curl -sS -o /dev/null -w '%{http_code}\\n' -X POST ${base}/v1/traces -H 'content-type: application/json' --data-binary @fixtures/sample-run-otel.json`,
  ['curl', '-sS', '-o', '/dev/null', '-w', '%{http_code}\\n', '-X', 'POST', `${base}/v1/traces`,
   '-H', 'content-type: application/json', '--data-binary', `@${otelFixture}`],
  { expectExit: 0 },
);

await runRaw(
  `curl -sS ${base}/api/runs -H 'authorization: Bearer demo-token' | head -c 200`,
  ['curl', '-sS', `${base}/api/runs`, '-H', 'authorization: Bearer demo-token'],
  { expectExit: 0 },
);

server.kill('SIGTERM');
await new Promise((r) => server.on('close', r));

await run(tg('list'), { expectExit: 0 });

/* ================================================================== *
 * Recipe: third-party verification                                    *
 * ================================================================== */

startSection('verification');

const outDir = join(WORK, 'out');
mkdirSync(outDir, { recursive: true });
const tgev = join(outDir, 'sdk-demo.tgev');
await run(tg('export', 'sdk-demo', '-o', tgev), { expectExit: 0 });
const clean = join(WORK, 'auditor-home');
mkdirSync(clean, { recursive: true });
await run(tg('verify', tgev), { env: { TRACEGLASS_HOME: clean }, expectExit: 0 });
await run(tg('verify', tgev, '--json'), { env: { TRACEGLASS_HOME: clean }, expectExit: 0 });
await run(['docs/test-vectors/check.mjs'], { command: 'node docs/test-vectors/check.mjs', expectExit: 0 });

/* ================================================================== */

writeFileSync(join(WORK, 'transcript.json'), JSON.stringify(sections, null, 2) + '\n');
const text = sections
  .map(
    (s) =>
      `##### ${s.title} #####\n\n` +
      s.entries
        .map((e) => `$ ${e.command}\n${e.output}\n[exit ${e.exitCode}]${e.note ? `\n(${e.note})` : ''}\n`)
        .join('\n'),
  )
  .join('\n');
writeFileSync(join(WORK, 'transcript.txt'), text);
console.log(`\nwrote ${join(WORK, 'transcript.txt')}`);
console.log(process.exitCode ? 'SOME STEPS DID NOT EXIT AS EXPECTED' : 'all steps exited as expected');
