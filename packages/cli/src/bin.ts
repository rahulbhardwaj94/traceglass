#!/usr/bin/env node
import {
  appendFileSync,
  existsSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import {
  RunStore,
  ingestAndFinalize,
  ingestClaudeCodeAndFinalize,
  discoverSessions,
  findSession,
  readSessionRecords,
  renderReport,
  verifyRunFull,
  readJournal,
  finalizeJournal,
  createEnvelope,
  parseEvidence,
  type Run,
  type SessionInfo,
} from '@traceglass/core';
import { dataDir, storePath } from './paths.js';
import { startServe, startServer } from './server.js';
import { openBrowser } from './open-browser.js';
import { generateKeys, maybeSign } from './keys.js';
import { FileAnchorSink, anchorRecordForRun, defaultAnchorsPath } from './anchors.js';

const program = new Command();
program
  .name('traceglass')
  .description('Flight recorder & tamper-evident audit dashboard for autonomous agents')
  .version('0.3.0');

function openStore(): RunStore {
  return new RunStore(storePath());
}

/** Reduce any thrown error (incl. Zod) to a single clear, in-voice line. */
function friendly(e: unknown): string {
  if (
    e &&
    typeof e === 'object' &&
    'issues' in e &&
    Array.isArray((e as { issues: unknown[] }).issues)
  ) {
    const issue = (e as { issues: Array<{ path: Array<string | number>; message: string }> })
      .issues[0];
    if (issue) return `invalid trace at "${issue.path.join('.') || '(root)'}" — ${issue.message}`;
  }
  return e instanceof Error ? (e.message.split('\n')[0] ?? e.message) : String(e);
}

function die(message: string): never {
  console.error(`✗ ${message}`);
  process.exit(1);
}

/** Ingest a trace file into the store (idempotent on a run id already present). */
function ingestFile(store: RunStore, file: string): Run {
  const path = resolve(file);
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return die(`Cannot read file: ${file}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return die(`${file} is not valid JSON.`);
  }
  let run: Run;
  try {
    run = maybeSign(ingestAndFinalize(json));
  } catch (e) {
    return die(`Could not read a run from ${file}: ${friendly(e)}`);
  }
  const existing = store.getRun(run.id);
  if (existing) {
    console.log(`Run "${run.id}" already ingested; re-opening the stored record.`);
    return existing;
  }
  store.saveRun(run);
  console.log(`Ingested run "${run.id}" (${run.totals.steps} steps).`);
  return run;
}

/** Ingest a Claude Code session into the store (idempotent on its run id). */
function ingestSession(store: RunStore, session: SessionInfo): Run {
  let run: Run;
  try {
    run = maybeSign(
      ingestClaudeCodeAndFinalize(readSessionRecords(session.file), {
        name: session.firstPrompt,
      }),
    );
  } catch (e) {
    return die(`Could not read session "${session.id}": ${friendly(e)}`);
  }
  const existing = store.getRun(run.id);
  if (existing) {
    console.log(`Session "${session.id}" already ingested; re-opening the stored record.`);
    return existing;
  }
  store.saveRun(run);
  console.log(`Ingested session "${session.id}" (${run.totals.steps} steps).`);
  return run;
}

/**
 * Serve the dashboard. With a runId, deep-links to that run; without one, boots
 * the session-picker landing screen (?picker=1).
 */
async function serveAndOpen(
  store: RunStore,
  runId: string | null,
  shouldOpen: boolean,
): Promise<void> {
  const server = await startServer(store);
  const target = runId
    ? `${server.url}/?run=${encodeURIComponent(runId)}`
    : `${server.url}/?picker=1`;
  console.log(`\n  traceglass dashboard → ${target}\n`);
  console.log('  Press Ctrl+C to stop.\n');
  if (shouldOpen) openBrowser(target);

  const shutdown = () => {
    server.close().finally(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

program
  .command('open')
  .description(
    'Ingest a trace file or Claude Code session (or re-open a stored run) and launch the dashboard',
  )
  .argument('[trace-file]', 'path to an OTel or native trace JSON file')
  .option('--id <runId>', 're-open an already-ingested run by id')
  .option(
    '--session <id>',
    'ingest + replay a Claude Code session by id (see `traceglass sessions`)',
  )
  .option('--no-open', 'do not auto-open the browser')
  .action(
    async (
      traceFile: string | undefined,
      opts: { id?: string; session?: string; open: boolean },
    ) => {
      const store = openStore();
      let runId: string | null = null;
      if (opts.id) {
        const run = store.getRun(opts.id);
        if (!run) {
          console.error(`No stored run with id "${opts.id}". Use \`traceglass list\`.`);
          process.exit(1);
        }
        runId = run.id;
      } else if (opts.session) {
        const session = findSession(opts.session);
        if (!session) {
          console.error(
            `No Claude Code session with id "${opts.session}". Use \`traceglass sessions\`.`,
          );
          process.exit(1);
        }
        runId = ingestSession(store, session).id;
      } else if (traceFile) {
        runId = ingestFile(store, traceFile).id;
      } else {
        // No target → boot the session picker landing screen.
        console.log('  No run specified — opening the session picker.');
      }
      await serveAndOpen(store, runId, opts.open);
    },
  );

program
  .command('sessions')
  .description('List discovered Claude Code sessions you can replay')
  .action(() => {
    const sessions = discoverSessions();
    if (sessions.length === 0) {
      console.log('No Claude Code sessions found under ~/.claude/projects.');
      return;
    }
    for (const s of sessions) {
      const when = s.endedAt ? s.endedAt.slice(0, 16).replace('T', ' ') : '—';
      const label = s.firstPrompt.length > 60 ? `${s.firstPrompt.slice(0, 57)}…` : s.firstPrompt;
      console.log(`${s.id}\t${when}\t${s.messageCount} msgs\t${s.project}\t${label}`);
    }
    console.log('\n  Replay one with: traceglass open --session <id>');
  });

program
  .command('demo')
  .description(
    'Open the dashboard on a bundled sample run (a collections agent stuck in a tool loop)',
  )
  .option('--no-open', 'do not auto-open the browser')
  .action(async (opts: { open: boolean }) => {
    const demoTrace = join(dirname(fileURLToPath(import.meta.url)), 'demo-trace.json');
    const store = openStore();
    const run = ingestFile(store, demoTrace);
    console.log(
      '  Tip: scrub the timeline to the loop, then run `traceglass verify` to see the hash chain.',
    );
    await serveAndOpen(store, run.id, opts.open);
  });

/**
 * Resolve a verify/report target: a local file path wins over a stored runId
 * (evidence files are self-contained — no store or keys needed to check them).
 */
function loadRunOrEvidence(store: RunStore, arg: string): Run {
  const asFile = resolve(arg);
  if (existsSync(asFile)) {
    try {
      return parseEvidence(JSON.parse(readFileSync(asFile, 'utf8')));
    } catch (e) {
      return die(`Could not read evidence from ${arg}: ${friendly(e)}`);
    }
  }
  const run = store.getRun(arg);
  if (!run) return die(`No stored run with id "${arg}" and no such file.`);
  return run;
}

program
  .command('verify')
  .description(
    'Verify a stored run or a .tgev evidence file (chain + signature); exit 1 if tampered',
  )
  .argument('<runId-or-file>', 'id of a stored run, or path to an exported evidence file')
  .action((arg: string) => {
    const store = openStore();
    const run = loadRunOrEvidence(store, arg);
    const result = verifyRunFull(run);
    console.log(result.chain.message);
    console.log(result.signature.message);
    console.log(`runHash: ${result.chain.storedRunHash}`);
    if (!result.ok) {
      if (!result.chain.ok) console.log(`expected: ${result.chain.expectedRunHash}`);
      process.exit(1);
    }
    store.close();
  });

program
  .command('report')
  .description('Write a standalone HTML audit report for a stored run or a .tgev evidence file')
  .argument('<runId-or-file>', 'id of a stored run, or path to an exported evidence file')
  .requiredOption('-o, --out <file>', 'output HTML file path')
  .action((arg: string, opts: { out: string }) => {
    const store = openStore();
    const run = loadRunOrEvidence(store, arg);
    writeFileSync(resolve(opts.out), renderReport(run));
    console.log(`Wrote audit report → ${opts.out}`);
    store.close();
  });

program
  .command('list')
  .description('List ingested runs')
  .action(() => {
    const store = openStore();
    const runs = store.listRuns();
    if (runs.length === 0) {
      console.log('No runs ingested yet. Try: traceglass open <trace-file>');
    } else {
      for (const r of runs) {
        console.log(
          `${r.id}\t${r.status}\t${r.steps} steps\t${r.currency} ${r.cost.toFixed(2)}\t${r.name}`,
        );
      }
    }
    store.close();
  });

program
  .command('serve')
  .description('Run as a collector: fixed port, authenticated ingest API, optional retention')
  .option('--port <port>', 'port to listen on', '4318')
  .option('--host <host>', 'host to bind (non-loopback requires a token)', '127.0.0.1')
  .option('--token <token>', 'bearer token for ingest (or set TRACEGLASS_TOKEN)')
  .option(
    '--retain <days>',
    'delete runs older than this many days (audited); default: keep forever',
  )
  .action(async (opts: { port: string; host: string; token?: string; retain?: string }) => {
    const store = openStore();
    const token = opts.token ?? process.env.TRACEGLASS_TOKEN;
    const retainDays = opts.retain !== undefined ? Number(opts.retain) : null;
    if (retainDays !== null && (!Number.isFinite(retainDays) || retainDays <= 0)) {
      return die('--retain must be a positive number of days.');
    }

    const auditPath = join(dataDir(), 'audit.jsonl');
    const sweep = () => {
      if (retainDays === null) return;
      const cutoff = new Date(Date.now() - retainDays * 24 * 60 * 60 * 1000).toISOString();
      const pruned = store.pruneOlderThan(cutoff);
      if (pruned.length > 0) {
        const now = new Date().toISOString();
        const lines = pruned
          .map((p) => JSON.stringify({ ...p, prunedAt: now, reason: 'retention', retainDays }))
          .join('\n');
        appendFileSync(auditPath, lines + '\n');
        console.log(
          `Retention: pruned ${pruned.length} run(s) older than ${retainDays}d (audited → ${auditPath}).`,
        );
      }
    };

    let server;
    try {
      server = await startServe(store, {
        port: Number(opts.port),
        host: opts.host,
        token,
        signer: maybeSign,
      });
    } catch (e) {
      return die(friendly(e));
    }
    sweep();
    const timer = retainDays !== null ? setInterval(sweep, 6 * 60 * 60 * 1000) : null;

    console.log(`\n  traceglass collector → ${server.url}`);
    console.log(`  Dashboard: ${server.url}/?picker=1`);
    console.log(`  Ingest:    curl -X POST ${server.url}/api/ingest \\`);
    console.log(
      `               -H 'content-type: application/json' ${token ? `-H "Authorization: Bearer $TRACEGLASS_TOKEN" ` : ''}\\`,
    );
    console.log(`               --data @trace.json`);
    console.log(`  OTLP/HTTP: POST ${server.url}/v1/traces`);
    console.log(
      `  Auth:      ${token ? 'bearer token required on POST' : 'loopback only, no token set'}`,
    );
    console.log(
      `  Retention: ${retainDays !== null ? `${retainDays} days (audited deletions)` : 'keep forever'}\n`,
    );
    console.log('  Press Ctrl+C to stop.\n');

    const shutdown = () => {
      if (timer) clearInterval(timer);
      server.close().finally(() => process.exit(0));
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  });

program
  .command('recover')
  .description(
    'Finalize orphaned recording journals (crashed SDK runs) into stored, verifiable runs',
  )
  .action(() => {
    const journalDir = join(dataDir(), 'journal');
    if (!existsSync(journalDir)) {
      console.log('No journals to recover.');
      return;
    }
    const files = readdirSync(journalDir).filter((f) => f.endsWith('.jsonl'));
    if (files.length === 0) {
      console.log('No journals to recover.');
      return;
    }
    const store = openStore();
    let recovered = 0;
    for (const f of files) {
      const file = join(journalDir, f);
      try {
        const contents = readJournal(file);
        if (store.getRun(contents.meta.id)) {
          console.log(`Journal ${f}: run already stored; removing journal.`);
          unlinkSync(file);
          continue;
        }
        const run = maybeSign(finalizeJournal(contents));
        store.saveRun(run);
        unlinkSync(file);
        recovered += 1;
        console.log(
          `Recovered "${run.id}" (${run.totals.steps} steps, status ${run.status}${run.status === 'failed' ? ' — recording did not end cleanly' : ''}).`,
        );
      } catch (e) {
        console.error(`✗ Journal ${f}: ${friendly(e)} (left in place)`);
      }
    }
    console.log(`Recovered ${recovered} run(s).`);
    store.close();
  });

program
  .command('keygen')
  .description('Generate a local Ed25519 signing keypair; new ingests are signed automatically')
  .option('--force', 'replace an existing keypair')
  .action((opts: { force?: boolean }) => {
    let result: ReturnType<typeof generateKeys>;
    try {
      result = generateKeys({ force: opts.force });
    } catch (e) {
      return die(friendly(e));
    }
    console.log(`Generated Ed25519 signing key (keyId ${result.keyId}).`);
    console.log(`Public key: ${result.publicKeyFile}`);
    console.log('New runs will be signed at ingest. The private key stays local (mode 0600).');
  });

program
  .command('export')
  .description(
    'Export a stored run as a portable .tgev evidence file, verifiable offline by anyone',
  )
  .argument('<runId>', 'id of a stored run')
  .option('-o, --out <file>', 'output file (default: run-<id>.tgev)')
  .action((runId: string, opts: { out?: string }) => {
    const store = openStore();
    const run = store.getRun(runId);
    if (!run) return die(`No stored run with id "${runId}".`);
    const out = resolve(opts.out ?? `run-${runId}.tgev`);
    writeFileSync(out, JSON.stringify(createEnvelope(run), null, 2));
    console.log(`Exported evidence → ${out}`);
    console.log(`runHash: ${run.runHash}`);
    console.log(
      run.signature
        ? `signed:  yes (keyId ${run.signature.keyId})`
        : 'signed:  no (run `traceglass keygen` to sign future ingests)',
    );
    console.log('Anyone can check it with: traceglass verify <file> — no store or keys needed.');
    store.close();
  });

program
  .command('anchor')
  .description(
    'Append run anchors (runHash + signature) to a JSONL file you can push to WORM storage',
  )
  .argument('[runId]', 'anchor a single stored run')
  .option('--all', 'anchor every stored run')
  .option('-o, --out <file>', 'anchors file (default: ~/.traceglass/anchors.jsonl)')
  .action(async (runId: string | undefined, opts: { all?: boolean; out?: string }) => {
    if (!runId && !opts.all) return die('Provide a runId or --all.');
    const store = openStore();
    const runs: Run[] = [];
    if (opts.all) {
      for (const summary of store.listRuns()) {
        const run = store.getRun(summary.id);
        if (run) runs.push(run);
      }
    } else if (runId) {
      const run = store.getRun(runId);
      if (!run) return die(`No stored run with id "${runId}".`);
      runs.push(run);
    }
    const sink = new FileAnchorSink(resolve(opts.out ?? defaultAnchorsPath()));
    const existing = sink.existingRunIds();
    const fresh = runs.filter((r) => !existing.has(r.id));
    await sink.append(fresh.map(anchorRecordForRun));
    const skipped = runs.length - fresh.length;
    console.log(
      `Anchored ${fresh.length} run(s)${skipped > 0 ? ` (${skipped} already anchored)` : ''} → ${resolve(opts.out ?? defaultAnchorsPath())}`,
    );
    store.close();
  });

program.parseAsync(process.argv);
